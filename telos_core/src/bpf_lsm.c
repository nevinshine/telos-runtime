// go:build ignore

/*
 * Telos Core - eBPF LSM Program
 *
 * Enforces taint-based access control at the kernel level.
 *
 * Hooks:
 *   - lsm/bprm_check_security: Block execve() for tainted processes
 *   - lsm/file_open: Block sensitive file access for tainted processes
 *
 * Build:
 *   clang -O2 -g -target bpf -c bpf_lsm.c -o bpf_lsm.o
 *
 * Requires: Linux 5.7+ with LSM BPF support (CONFIG_BPF_LSM=y)
 */

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Include shared definitions
#include "../maps/mirage_maps.h" // Phase 4 Active Deception
#include "../maps/process_map.h"

// EPERM is not available in BPF, define it
#ifndef EPERM
#define EPERM 1
#endif

// === LICENSE ===
char LICENSE[] SEC("license") = "GPL";

// === MAPS ===

// Process taint map: PID -> process_info_t
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32); // PID
  __type(value, struct process_info_t);
} process_map SEC(".maps");

// Configuration map: index -> config value
// Note: Named telos_config_t to avoid conflict with vmlinux.h's config_t
struct telos_config_t {
  __u32 max_taint_for_exec; // Threshold for blocking execve
  __u32 max_taint_for_open; // Threshold for blocking file open
  __u32 enabled;            // 0 = audit only, 1 = enforce
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct telos_config_t);
} config_map SEC(".maps");

// Ringbuf for sending events to userspace (audit log)
struct event_t {
  __u64 context_val;
  __u32 pid;
  __u32 taint_level;
  __u32 blocked;
  char comm[16];
  char action[16];
  __u32 padding;
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024); // 256 KB
} events SEC(".maps");

// Inode policy map: Inode Number -> Sensitivity Level
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64); // Inode Number
  __type(value, struct inode_policy_t);
} inode_map SEC(".maps");

// Network allowlist map: IPv4 Address -> Allowed
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32); // IPv4 Address
  __type(value, struct network_policy_t);
} network_map SEC(".maps");

// [Phase 5] Execution Allowlist map: PID -> exec_policy_t
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32); // PID
  __type(value, struct exec_policy_t);
} exec_policy_map SEC(".maps");

// [Phase 2] Tainted mmap inode map: tracks shared memory mappings created by
// tainted processes. Any clean process that maps the same inode inherits taint.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u64);  // Inode number of the mapped file
  __type(value, __u32); // Taint level of the originator
} tainted_mmap_map SEC(".maps");

// [Phase 2] Tainted SysV shmid map: tracks System V shared memory segments
// created or attached by tainted processes.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);  // shmid
  __type(value, __u32); // Taint level of the originator
} tainted_shmid_map SEC(".maps");

// [Phase 4] Tainted IPC map: tracks anonymous inodes (pipes/socketpairs)
// used for propagating taint across un-named file descriptors.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u64);  // Inode number of the pipe/socket
  __type(value, __u32); // Taint level of the originator
} tainted_ipc_map SEC(".maps");

// [Phase 7] Task Storage for Taint
// Stores taint directly on the kernel task_struct, auto-cleaned on exit
struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, __u32); // Taint level
} task_taint_storage SEC(".maps");

// [Phase 7] Socket Storage for Taint
// Stores taint directly on the kernel sock struct, auto-cleaned on close
struct {
  __uint(type, BPF_MAP_TYPE_SK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, __u32); // Taint level
} sk_taint_storage SEC(".maps");

// Define AF_INET if missing
#ifndef AF_INET
#define AF_INET 2
#endif

// === HELPER FUNCTIONS ===

static __always_inline struct telos_config_t *get_config(void) {
  __u32 key = 0;
  return bpf_map_lookup_elem(&config_map, &key);
}

static __always_inline void emit_event(__u32 pid, __u32 taint, __u32 blocked,
                                       const char *action, __u64 context_val) {
  struct event_t *event;

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event)
    return;

  event->context_val = context_val;
  event->pid = pid;
  event->taint_level = taint;
  event->blocked = blocked;
  event->padding = 0;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  // Copy action string (max 15 chars + null)
  __builtin_memcpy(event->action, action, 15);

  bpf_ringbuf_submit(event, 0);
}

// === LSM HOOKS ===

/*
 * Hook: bprm_check_security
 *
 * Phase 5: Intent-Based Execution Gate
 *
 * Called before execve() is allowed to proceed.
 * Two-layer enforcement:
 *   Layer 1: Taint check (legacy, catches compromised processes)
 *   Layer 2: Intent-based allowlist (Phase 5, restricts binaries per-intent)
 *
 * IMPORTANT: We also check the PARENT's taint level, because when a
 * tainted process forks and execs, the child has a new PID that isn't
 * in our map yet, but we should still block it.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(telos_check_exec, struct linux_binprm *bprm) {
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  __u32 effective_taint = TAINT_CLEAN;
  struct process_info_t *info = NULL;

  // Get config
  struct telos_config_t *config = get_config();
  __u32 max_taint = config ? config->max_taint_for_exec : TAINT_MEDIUM;
  __u32 enforce = config ? config->enabled : 1;

  // === Layer 1: Taint Check (Legacy Fallback) ===
  info = bpf_map_lookup_elem(&process_map, &pid);
  if (info) {
    effective_taint = info->taint_level;
  } else {
    // Not tracked directly - check PARENT process
    struct task_struct *current_task =
        (struct task_struct *)bpf_get_current_task();
    if (current_task) {
      __u32 ppid = BPF_CORE_READ(current_task, real_parent, tgid);
      struct process_info_t *parent_info =
          bpf_map_lookup_elem(&process_map, &ppid);
      if (parent_info) {
        effective_taint = parent_info->taint_level;
      }
    }
  }

  // Check if taint exceeds threshold
  if (effective_taint > max_taint) {
    emit_event(pid, effective_taint, 1, "exec_tainted", 0);
    if (enforce) {
      return -EPERM;
    }
  }

  // === Layer 2: Intent-Based Execution Allowlist (Phase 5) ===
  struct exec_policy_t *policy = bpf_map_lookup_elem(&exec_policy_map, &pid);

  // Inheritance: If the child isn't tracked, lookup the parent's policy.
  // This prevents attackers from bypassing the execution gate via fork/exec.
  if (!policy) {
    struct task_struct *current_task =
        (struct task_struct *)bpf_get_current_task();
    if (current_task) {
      __u32 ppid = BPF_CORE_READ(current_task, real_parent, tgid);
      policy = bpf_map_lookup_elem(&exec_policy_map, &ppid);
    }
  }

  // If policy exists and is in enforce mode (1)
  if (policy && policy->mode == 1) {
    char filename[16] = {0};

    // Extract binary name being executed
    bpf_probe_read_kernel_str(
        &filename, sizeof(filename),
        BPF_CORE_READ(bprm, file, f_path.dentry, d_name.name));

    bool matched = false;

// BPF Verifier bounded loop checking up to 8 allowed binaries
#pragma unroll
    for (int i = 0; i < 8; i++) {
      if (policy->allowed_bins[i][0] == '\0') {
        continue; // Empty slot
      }

      bool is_match = true;
      for (int j = 0; j < 16; j++) {
        if (filename[j] != policy->allowed_bins[i][j]) {
          is_match = false;
          break;
        }
        // If we reached the end of both strings simultaneously and they match
        if (filename[j] == '\0') {
          break;
        }
      }

      if (is_match) {
        matched = true;
        break;
      }
    }

    if (!matched) {
      emit_event(pid, effective_taint, 1, "exec_denied", 0);
      if (enforce) {
        return -EPERM;
      }
    }
  }

  return 0; // Allow
}

/*
 * Hook: file_open
 *
 * Called when a file is opened. We block access to sensitive files
 * (like SSH keys) from tainted processes.
 */
SEC("lsm/file_open")
int BPF_PROG(telos_check_file, struct file *file) {
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  __u32 tracked_pid = pid;

  // Lookup process in taint map
  struct process_info_t *info = bpf_map_lookup_elem(&process_map, &tracked_pid);
  if (!info) {
    // Not tracked directly - check PARENT process
    struct task_struct *current_task =
        (struct task_struct *)bpf_get_current_task();
    if (current_task) {
      tracked_pid = BPF_CORE_READ(current_task, real_parent, tgid);
      info = bpf_map_lookup_elem(&process_map, &tracked_pid);
    }
  }

  if (!info) {
    // Not a tracked process - allow
    return 0;
  }

  // Get config
  struct telos_config_t *config = get_config();
  __u32 max_taint = config ? config->max_taint_for_open : TAINT_HIGH;
  __u32 enforce = config ? config->enabled : 1;

  // Get the dentry to check inode
  struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
  if (!dentry)
    return 0;

  // Retrieve Inode Number
  struct inode *inode = BPF_CORE_READ(dentry, d_inode);
  if (!inode)
    return 0;

  __u64 ino = BPF_CORE_READ(inode, i_ino);

  // [MIRAGE HANDOFF] Check if this inode is slated for deception
  if (info->taint_level >= max_taint) {
    __u32 *honey_id = bpf_map_lookup_elem(&mirage_map, &ino);
    if (honey_id) {
      // Emit audit event but DO NOT BLOCK. Hand off to ksys_read interceptor.
      emit_event(pid, info->taint_level, 0, "mirage_trap", ino);
      return 0; // ALLOW!
    }
  }

  // Check Inode Map
  struct inode_policy_t *policy = bpf_map_lookup_elem(&inode_map, &ino);
  if (policy && policy->sensitivity > 0) {
    // Phase 7: Data-Flow Taint Tracking (Dynamic IFC)
    // If the process is currently clean but touches a highly sensitive file,
    // we mutate its state in real-time.
    if (policy->sensitivity >= 2 && info->taint_level < TAINT_CRITICAL) {
      info->taint_level = TAINT_CRITICAL;
      bpf_map_update_elem(&process_map, &tracked_pid, info, BPF_ANY);
      emit_event(tracked_pid, info->taint_level, 0, "taint_elevate", ino);
    }

    // Now enforce the policy against the mutated (or existing) taint level
    if (info->taint_level >= max_taint) {
      // Inode is sensitive!
      emit_event(tracked_pid, info->taint_level, 1, "open_inode", ino);

      if (enforce) {
        return -EPERM;
      }
    }
  }

  return 0; // Allow
}

// Define AF_INET6 if missing from vmlinux.h or headers
#ifndef AF_INET6
#define AF_INET6 10
#endif

/*
 * Hook: socket_connect
 *
 * Control network connections. Tainted processes can only connect
 * to explicitly whitelisted IPs.
 */
SEC("lsm/socket_connect")
int BPF_PROG(telos_check_connect, struct socket *sock, struct sockaddr *address,
             int addrlen) {
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  __u32 tracked_pid = pid;

  // Lookup process
  struct process_info_t *info = bpf_map_lookup_elem(&process_map, &tracked_pid);
  if (!info) {
    // Not tracked directly - check PARENT process
    struct task_struct *current_task =
        (struct task_struct *)bpf_get_current_task();
    if (current_task) {
      tracked_pid = BPF_CORE_READ(current_task, real_parent, tgid);
      info = bpf_map_lookup_elem(&process_map, &tracked_pid);
    }
  }

  if (!info)
    return 0; // Not tracked -> Allow daemon connections

  // Get config
  struct telos_config_t *config = get_config();
  __u32 enforce = config ? config->enabled : 1;

  // Phase 7: Dynamic Information Flow Control (IFC) Slam
  // If the agent read a highly sensitive file, its taint was elevated to
  // CRITICAL. We MUST instantly drop all network connections to prevent data
  // exfiltration, regardless of what the AI explicitly allowed in the network
  // map.
  __u64 context_val = 0;
  if (address && address->sa_family == AF_INET) {
    struct sockaddr_in *addr = (struct sockaddr_in *)address;
    context_val = addr->sin_addr.s_addr;
  }

  if (info->taint_level >= TAINT_CRITICAL) {
    emit_event(tracked_pid, info->taint_level, 1, "exfil_blocked", context_val);
    if (enforce) {
      return -EPERM;
    }
  }

  // 1. Blackhole IPv6 for tracked AI agents to prevent firewall bypass
  if (address->sa_family == AF_INET6) {
    emit_event(tracked_pid, info->taint_level, 1, "connect_ipv6_denied", 0);
    if (enforce) {
      return -EPERM;
    }
  }

  // 2. Allow local Unix sockets (IPC) and other non-IPv4 families
  if (address->sa_family != AF_INET) {
    return 0;
  }

  struct sockaddr_in *addr = (struct sockaddr_in *)address;
  __u32 dest_ip = addr->sin_addr.s_addr;

  // Check Allowlist
  struct network_policy_t *policy = bpf_map_lookup_elem(&network_map, &dest_ip);
  if (!policy || policy->allowed != 1) {
    // Block! ALL tracked processes are blocked by default unless allowed.
    emit_event(pid, info->taint_level, 1, "connect_denied", dest_ip);

    if (enforce) {
      return -EPERM;
    }
  }

  return 0;
}

/*
 * Hook: sched_process_fork
 *
 * Track process creation to propagate taint to child processes.
 * If a tracked process forks, the child inherits the taint synchronously
 * before it can run.
 */
SEC("tp/sched/sched_process_fork")
int telos_sched_fork(struct trace_event_raw_sched_process_fork *ctx) {
  __u32 parent_pid = ctx->parent_pid;

  // Check if parent is tracked
  struct process_info_t *parent_info =
      bpf_map_lookup_elem(&process_map, &parent_pid);
  if (!parent_info) {
    return 0; // Parent not tracked
  }

  // If parent is tracked (including tainted), propagate to child instantly
  struct process_info_t child_info = *parent_info;
  child_info.pid = ctx->child_pid;

  bpf_map_update_elem(&process_map, &child_info.pid, &child_info, BPF_ANY);

  // Emit event to userspace (Daemon) for SIEM logging and Prometheus metrics
  emit_event(child_info.pid, child_info.taint_level, 0, "fork_taint", 0);

  return 0;
}

// ============================================================
// PHASE 2: ENHANCED TAINT PROVENANCE & IPC TRACKING
// ============================================================

/*
 * Hook: mmap_file
 *
 * Intercepts mmap() calls to track cross-process taint propagation
 * via shared memory mappings.
 *
 * If a TAINT_HIGH+ process creates a MAP_SHARED mapping, the backing
 * file's inode is recorded. Any clean process that subsequently maps
 * the same inode inherits the taint, closing the thread-laundering
 * bypass vector described in the architecture report.
 */
SEC("lsm/mmap_file")
int BPF_PROG(telos_check_mmap, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags) {
  if (!file)
    return 0; // Anonymous mappings (no backing file) - allow

  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct process_info_t *info = bpf_map_lookup_elem(&process_map, &pid);

  // Get the inode of the backing file
  struct inode *inode = BPF_CORE_READ(file, f_inode);
  if (!inode)
    return 0;
  __u64 ino = BPF_CORE_READ(inode, i_ino);

  // Check if this is a shared mapping (MAP_SHARED = 0x01)
  if (!(flags & 0x01))
    return 0; // Private mapping, no cross-process risk

  if (info && info->taint_level >= TAINT_HIGH) {
    // Tainted process is creating a shared mapping.
    // Record the inode so any future mapper inherits the taint.
    __u32 taint = info->taint_level;
    bpf_map_update_elem(&tainted_mmap_map, &ino, &taint, BPF_ANY);
    emit_event(pid, info->taint_level, 0, "mmap_taint_src", ino);
  } else {
    // Clean process is mapping. Check if the inode is already tainted.
    __u32 *existing_taint = bpf_map_lookup_elem(&tainted_mmap_map, &ino);
    if (existing_taint && *existing_taint >= TAINT_HIGH) {
      // Propagate taint to this clean process
      if (info) {
        info->taint_level = *existing_taint;
        bpf_map_update_elem(&process_map, &pid, info, BPF_ANY);
      } else {
        // Process not tracked yet, create a new entry
        struct process_info_t new_info = {};
        new_info.pid = pid;
        new_info.taint_level = *existing_taint;
        bpf_get_current_comm(&new_info.comm, sizeof(new_info.comm));
        bpf_map_update_elem(&process_map, &pid, &new_info, BPF_ANY);
      }
      emit_event(pid, *existing_taint, 0, "mmap_taint_inh", ino);
    }
  }

  return 0; // Always allow mmap (taint propagation is passive)
}

/*
 * Hook: ptrace_access_check
 *
 * Blocks ptrace() calls where the target process holds TAINT_HIGH+.
 * This prevents a clean process from using PTRACE_PEEKDATA to read
 * sensitive data out of a tainted process's memory space, effectively
 * bypassing the IFC boundary.
 */
SEC("lsm/ptrace_access_check")
int BPF_PROG(telos_check_ptrace, struct task_struct *child,
             unsigned int mode) {
  // Get the target (child) PID
  __u32 child_pid = BPF_CORE_READ(child, tgid);

  // Check if the target is tainted
  struct process_info_t *child_info =
      bpf_map_lookup_elem(&process_map, &child_pid);
  if (!child_info)
    return 0; // Target not tracked, allow

  if (child_info->taint_level >= TAINT_HIGH) {
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;
    emit_event(caller_pid, child_info->taint_level, 1, "ptrace_denied", child_pid);

    struct telos_config_t *config = get_config();
    __u32 enforce = config ? config->enabled : 1;
    if (enforce) {
      return -EPERM; // Block ptrace into tainted process
    }
  }

  return 0;
}

/*
 * Hook: shm_shmat
 *
 * Intercepts System V shared memory attachment (shmat).
 * If the shared memory segment was created/attached by a tainted process,
 * any process that attaches inherits the taint.
 *
 * Note: We use the shmid (embedded in the shp struct) to track taint.
 */
SEC("lsm/shm_shmat")
int BPF_PROG(telos_check_shmat, struct kern_ipc_perm *shp, char *shmaddr,
             int shmflg) {
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct process_info_t *info = bpf_map_lookup_elem(&process_map, &pid);

  // Use the IPC object's id as our tracking key
  __u32 ipc_id = BPF_CORE_READ(shp, id);

  if (info && info->taint_level >= TAINT_HIGH) {
    // Tainted process is attaching. Mark the segment.
    __u32 taint = info->taint_level;
    bpf_map_update_elem(&tainted_shmid_map, &ipc_id, &taint, BPF_ANY);
    emit_event(pid, info->taint_level, 0, "shmat_taint_src", ipc_id);
  } else {
    // Clean process is attaching. Check if segment is tainted.
    __u32 *existing_taint = bpf_map_lookup_elem(&tainted_shmid_map, &ipc_id);
    if (existing_taint && *existing_taint >= TAINT_HIGH) {
      if (info) {
        info->taint_level = *existing_taint;
        bpf_map_update_elem(&process_map, &pid, info, BPF_ANY);
      } else {
        struct process_info_t new_info = {};
        new_info.pid = pid;
        new_info.taint_level = *existing_taint;
        bpf_get_current_comm(&new_info.comm, sizeof(new_info.comm));
        bpf_map_update_elem(&process_map, &pid, &new_info, BPF_ANY);
      }
      emit_event(pid, *existing_taint, 0, "shmat_taint_inh", ipc_id);
    }
  }

  return 0; // Always allow attachment (taint propagation is passive)
}

/*
 * Hook: file_permission
 *
 * Tracks cross-process taint propagation via pipes and socketpairs.
 * If a tainted process writes to an anonymous pipe/socket, its inode is tainted.
 * If a clean process reads from a tainted pipe/socket, it inherits the taint.
 * This is highly optimized and only triggers for S_IFIFO and S_IFSOCK.
 */
SEC("lsm/file_permission")
int BPF_PROG(telos_check_file_permission, struct file *file, int mask) {
  if (!file) return 0;
  
  struct inode *inode = BPF_CORE_READ(file, f_inode);
  if (!inode) return 0;
  
  // Only track pipes (FIFO) and sockets
  // S_IFMT = 0170000, S_IFIFO = 0010000, S_IFSOCK = 0140000
  unsigned short mode = BPF_CORE_READ(inode, i_mode);
  if ((mode & 0170000) != 0010000 && (mode & 0170000) != 0140000) {
    return 0; // Not a pipe or socket
  }
  
  __u64 ino = BPF_CORE_READ(inode, i_ino);
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct process_info_t *info = bpf_map_lookup_elem(&process_map, &pid);
  
  // 1. MAY_WRITE: Taint the pipe if writer is tainted
  if (mask & 2) { // MAY_WRITE = 2
    if (info && info->taint_level >= TAINT_HIGH) {
      __u32 taint = info->taint_level;
      bpf_map_update_elem(&tainted_ipc_map, &ino, &taint, BPF_ANY);
      emit_event(pid, info->taint_level, 0, "pipe_taint_src", ino);
    }
  }
  
  // 2. MAY_READ: Inherit taint if pipe is tainted
  if (mask & 1) { // MAY_READ = 1
    __u32 *existing_taint = bpf_map_lookup_elem(&tainted_ipc_map, &ino);
    if (existing_taint && *existing_taint >= TAINT_HIGH) {
      if (!info || info->taint_level < *existing_taint) {
        if (info) {
          info->taint_level = *existing_taint;
          bpf_map_update_elem(&process_map, &pid, info, BPF_ANY);
        } else {
          struct process_info_t new_info = {};
          new_info.pid = pid;
          new_info.taint_level = *existing_taint;
          bpf_get_current_comm(&new_info.comm, sizeof(new_info.comm));
          bpf_map_update_elem(&process_map, &pid, &new_info, BPF_ANY);
        }
        emit_event(pid, *existing_taint, 0, "pipe_taint_inh", ino);
      }
    }
  }
  
  return 0;
}

/*
 * Hook: file_receive
 *
 * Intercepts file descriptors passed between processes via SCM_RIGHTS
 * over Unix domain sockets, preventing capability delegation bypasses.
 */
SEC("lsm/file_receive")
int BPF_PROG(telos_check_file_receive, struct file *file) {
  if (!file) return 0;
  
  struct inode *inode = BPF_CORE_READ(file, f_inode);
  if (!inode) return 0;
  
  __u64 ino = BPF_CORE_READ(inode, i_ino);
  __u32 *existing_taint = bpf_map_lookup_elem(&tainted_ipc_map, &ino);
  
  // If the received file descriptor points to a tainted IPC channel,
  // taint the receiving process instantly upon reception.
  if (existing_taint && *existing_taint >= TAINT_HIGH) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct process_info_t *info = bpf_map_lookup_elem(&process_map, &pid);
    if (!info || info->taint_level < *existing_taint) {
      if (info) {
        info->taint_level = *existing_taint;
        bpf_map_update_elem(&process_map, &pid, info, BPF_ANY);
      } else {
        struct process_info_t new_info = {};
        new_info.pid = pid;
        new_info.taint_level = *existing_taint;
        bpf_get_current_comm(&new_info.comm, sizeof(new_info.comm));
        bpf_map_update_elem(&process_map, &pid, &new_info, BPF_ANY);
      }
      emit_event(pid, *existing_taint, 0, "scm_rights_inh", ino);
    }
  }
  
  return 0;
}

/*
 * Phase 7: Deep Kernel Pivot - Cross-Process Taint Tracking
 * Hook: unix_stream_connect
 *
 * Taints a UNIX domain socket when a tainted process initiates a connection.
 */
SEC("lsm/unix_stream_connect")
int BPF_PROG(telos_check_unix_stream_connect, struct sock *sock, struct sock *other, struct sock *newsk) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
  __u32 *task_taint = bpf_task_storage_get(&task_taint_storage, task, 0, 0);

  if (task_taint && *task_taint >= TAINT_HIGH) {
    // Taint the server socket (other)
    if (other) {
      __u32 *server_taint = bpf_sk_storage_get(&sk_taint_storage, other, 0, BPF_SK_STORAGE_GET_F_CREATE);
      if (server_taint) *server_taint = *task_taint;
    }
    
    // Taint the newly spawned connection socket (newsk)
    if (newsk) {
      __u32 *conn_taint = bpf_sk_storage_get(&sk_taint_storage, newsk, 0, BPF_SK_STORAGE_GET_F_CREATE);
      if (conn_taint) *conn_taint = *task_taint;
    }
  } else {
     // Check if we are connecting to a tainted server
     if (other) {
         __u32 *server_taint = bpf_sk_storage_get(&sk_taint_storage, other, 0, 0);
         if (server_taint && *server_taint >= TAINT_HIGH) {
             // Inherit taint to our task
             __u32 *our_taint = bpf_task_storage_get(&task_taint_storage, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
             if (our_taint) *our_taint = *server_taint;
             
             // Update global map for Cortex visibility
             __u32 pid = bpf_get_current_pid_tgid() >> 32;
             struct process_info_t *info = bpf_map_lookup_elem(&process_map, &pid);
             if (info) {
                 info->taint_level = *server_taint;
                 bpf_map_update_elem(&process_map, &pid, info, BPF_ANY);
             } else {
                struct process_info_t new_info = {};
                new_info.pid = pid;
                new_info.taint_level = *server_taint;
                bpf_get_current_comm(&new_info.comm, sizeof(new_info.comm));
                bpf_map_update_elem(&process_map, &pid, &new_info, BPF_ANY);
             }
             emit_event(pid, *server_taint, 0, "unix_conn_inh", 0);
         }
     }
  }

  return 0;
}

/*
 * Phase 7: Hook: socket_sock_rcv_skb
 *
 * Inherits taint when a clean process receives a packet on a tainted socket.
 * This effectively passes the taint from the socket layer to the task_struct.
 */
SEC("lsm/socket_sock_rcv_skb")
int BPF_PROG(telos_check_socket_sock_rcv_skb, struct sock *sk, struct sk_buff *skb) {
    if (!sk) return 0;
    
    // Check if the socket is tainted
    __u32 *sk_taint = bpf_sk_storage_get(&sk_taint_storage, sk, 0, 0);
    if (sk_taint && *sk_taint >= TAINT_HIGH) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
        __u32 *task_taint = bpf_task_storage_get(&task_taint_storage, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
        
        // Inherit the taint
        if (task_taint && *task_taint < *sk_taint) {
            *task_taint = *sk_taint;
            
            // Sync with global map
            __u32 pid = bpf_get_current_pid_tgid() >> 32;
            struct process_info_t *info = bpf_map_lookup_elem(&process_map, &pid);
            if (info) {
                 info->taint_level = *sk_taint;
                 bpf_map_update_elem(&process_map, &pid, info, BPF_ANY);
            } else {
                 struct process_info_t new_info = {};
                 new_info.pid = pid;
                 new_info.taint_level = *sk_taint;
                 bpf_get_current_comm(&new_info.comm, sizeof(new_info.comm));
                 bpf_map_update_elem(&process_map, &pid, &new_info, BPF_ANY);
            }
            emit_event(pid, *sk_taint, 0, "socket_recv_inh", 0);
        }
    }
    
    return 0;
}

/*
 * NEW Hook: ksys_read ENTRY
 * Resolve FD -> Inode, check Mirage map, stash user buffer.
 */
SEC("kprobe/ksys_read")
int BPF_KPROBE(mirage_read_enter, unsigned int fd, char *buf, size_t count) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;

  struct process_info_t *info = bpf_map_lookup_elem(&process_map, &pid);
  if (!info || info->taint_level < TAINT_HIGH)
    return 0; // Only deceive tainted agents

  // 1. Resolve FD to Inode using BPF CO-RE
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  // Safety checks required by verifier for pointer walking
  struct files_struct *files = BPF_CORE_READ(task, files);
  if (!files)
    return 0;

  struct fdtable *fdt = BPF_CORE_READ(files, fdt);
  if (!fdt || fd >= BPF_CORE_READ(fdt, max_fds))
    return 0;

  struct file **fd_array = BPF_CORE_READ(fdt, fd);
  if (!fd_array)
    return 0;

  struct file *f = NULL;
  bpf_probe_read_kernel(&f, sizeof(struct file *),
                        &fd_array[fd]); // The actual struct file
  if (!f)
    return 0;

  struct inode *inode = BPF_CORE_READ(f, f_inode);
  if (!inode)
    return 0;

  __u64 ino = BPF_CORE_READ(inode, i_ino);

  // 2. Check if Inode is in Mirage Map
  __u32 *honey_id = bpf_map_lookup_elem(&mirage_map, &ino);
  if (!honey_id)
    return 0; // Normal file

  // 3. Stash State for kretprobe
  struct active_mirage_read_t state = {};
  state.user_buf = (void *)buf;
  state.requested_count = count;
  state.honey_id = *honey_id;

  bpf_map_update_elem(&active_mirage_reads, &pid_tgid, &state, BPF_ANY);
  return 0;
}

/*
 * NEW Hook: ksys_read EXIT
 * Overwrite the buffer with the honey token.
 */
SEC("kretprobe/ksys_read")
int BPF_KRETPROBE(mirage_read_exit) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();

  struct active_mirage_read_t *state =
      bpf_map_lookup_elem(&active_mirage_reads, &pid_tgid);
  if (!state)
    return 0;

  long bytes_read = PT_REGS_RC(ctx);

  if (bytes_read > 0) {
    struct honey_payload_t *payload =
        bpf_map_lookup_elem(&honey_data_map, &state->honey_id);
    if (payload) {
      __u32 write_len = payload->length;

      // Ensure write_len is bounded for the verifier
      if (write_len > 256)
        write_len = 256;

      // Safety Truncation: Never write more than kernel read
      if (bytes_read > 0 && bytes_read < 256) {
        if (write_len > bytes_read) {
          write_len = bytes_read;
        }
      }

      // Hard-bound for BPF verifier using bitwise operations
      write_len &= 0xFF; // Binds to [0, 255]

      if (write_len > 0) {
        long err =
            bpf_probe_write_user(state->user_buf, payload->data, write_len);
        if (err == 0) {
          emit_event(pid_tgid >> 32, TAINT_CRITICAL, 0, "mirage_fed", 0);
        }
      }
    }
  }

  bpf_map_delete_elem(&active_mirage_reads, &pid_tgid);
  return 0;
}

/*
 * ==========================================
 * PHASE 4: THE ILLUSIONIST (Metadata Spoofing)
 * ==========================================
 * Spoof stat.st_size for honey-files so `ls -l`
 * and file buffers see the fake size, not the padded real size.
 *
 * We hook the syscall entries to grab the user `statbuf` pointer (safe for
 * bpf_probe_write_user), and vfs_getattr (shared inner function) to verify
 * the target inode against the Mirage Map.
 */

struct active_fstat_state_t {
  void *statbuf;
  __u32 honey_id;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u64); // PID/TID
  __type(value, struct active_fstat_state_t);
} active_fstats SEC(".maps");

// 1A. Entry to newfstatat (handles stat, lstat, fstatat)
SEC("kprobe/__x64_sys_newfstatat")
int BPF_KPROBE(mirage_sys_newfstatat_enter, struct pt_regs *regs) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;

  struct process_info_t *info = bpf_map_lookup_elem(&process_map, &pid);
  if (!info || info->taint_level < TAINT_HIGH)
    return 0; // Only deceive tainted agents

  struct active_fstat_state_t state = {};

  void *statbuf = NULL;
  // The 3rd argument is struct stat __user *statbuf (dx register on x86_64)
  // Safely read it using bpf_probe_read_kernel to satisfy the verifier
  bpf_probe_read_kernel(&statbuf, sizeof(statbuf), &regs->dx);

  state.statbuf = statbuf;
  state.honey_id = 0; // Unknown until vfs_getattr resolves the inode

  bpf_map_update_elem(&active_fstats, &pid_tgid, &state, BPF_ANY);
  return 0;
}

// 1B. Entry to newfstat (handles fstat)
SEC("kprobe/__x64_sys_newfstat")
int BPF_KPROBE(mirage_sys_newfstat_enter, struct pt_regs *regs) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;

  struct process_info_t *info = bpf_map_lookup_elem(&process_map, &pid);
  if (!info || info->taint_level < TAINT_HIGH)
    return 0;

  struct active_fstat_state_t state = {};

  void *statbuf = NULL;
  // The 2nd argument is struct stat __user *statbuf (si register on x86_64)
  bpf_probe_read_kernel(&statbuf, sizeof(statbuf), &regs->si);

  state.statbuf = statbuf;
  state.honey_id = 0;

  bpf_map_update_elem(&active_fstats, &pid_tgid, &state, BPF_ANY);
  return 0;
}

// 2. Inner lookup inside vfs_getattr to get the inode
SEC("kprobe/vfs_getattr")
int BPF_KPROBE(mirage_getattr_enter, const struct path *path,
               struct kstat *stat) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();

  struct active_fstat_state_t *state =
      bpf_map_lookup_elem(&active_fstats, &pid_tgid);
  if (!state)
    return 0; // Not inside a tracked stat syscall

  struct dentry *dentry = BPF_CORE_READ(path, dentry);
  if (!dentry)
    return 0;
  struct inode *inode = BPF_CORE_READ(dentry, d_inode);
  if (!inode)
    return 0;
  __u64 ino = BPF_CORE_READ(inode, i_ino);

  // Check if Inode is in Mirage Map
  __u32 *honey_id = bpf_map_lookup_elem(&mirage_map, &ino);
  if (honey_id) {
    state->honey_id = *honey_id; // Mark for spoofing!
  }
  return 0;
}

// Helper for Exits
static __always_inline int mirage_fstat_exit(struct pt_regs *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();

  struct active_fstat_state_t *state =
      bpf_map_lookup_elem(&active_fstats, &pid_tgid);
  if (!state)
    return 0;

  int ret = PT_REGS_RC(ctx);
  // If stat succeeded and it's a honey file
  if (ret == 0 && state->honey_id != 0 && state->statbuf != NULL) {
    struct honey_payload_t *payload =
        bpf_map_lookup_elem(&honey_data_map, &state->honey_id);
    if (payload) {
      long fake_size = payload->length;
      // bpf_probe_write_user is safe here because statbuf is a user pointer.
      // Offset 48 is struct stat.st_size on x86_64
      void *size_ptr = (void *)((char *)state->statbuf + 48);
      bpf_probe_write_user(size_ptr, &fake_size, sizeof(fake_size));
    }
  }

  bpf_map_delete_elem(&active_fstats, &pid_tgid);
  return 0;
}

// 3A. Exit from newfstatat
SEC("kretprobe/__x64_sys_newfstatat")
int BPF_KRETPROBE(mirage_sys_newfstatat_exit) { return mirage_fstat_exit(ctx); }

// 3B. Exit from newfstat
SEC("kretprobe/__x64_sys_newfstat")
int BPF_KRETPROBE(mirage_sys_newfstat_exit) { return mirage_fstat_exit(ctx); }

// ==========================================
// PHASE 11: LIFECYCLE CLEANUP (LRU Fix)
// ==========================================
// Explicitly free resources from HASH maps when
// the underlying kernel objects are destroyed to
// prevent map exhaustion.

/*
 * Hook: task_free
 * Cleans up process-specific maps when a task terminates.
 */
SEC("lsm/task_free")
int BPF_PROG(telos_task_free, struct task_struct *task) {
  __u32 pid = BPF_CORE_READ(task, tgid);
  bpf_map_delete_elem(&process_map, &pid);
  bpf_map_delete_elem(&exec_policy_map, &pid);
  return 0;
}

/*
 * Hook: inode_free_security
 * Cleans up inode-specific taint maps when an inode is destroyed.
 */
SEC("lsm/inode_free_security")
int BPF_PROG(telos_inode_free, struct inode *inode) {
  __u64 ino = BPF_CORE_READ(inode, i_ino);
  bpf_map_delete_elem(&tainted_mmap_map, &ino);
  return 0;
}

/*
 * Hook: shm_free_security
 * Cleans up IPC shared memory taint maps when destroyed.
 */
SEC("lsm/shm_free_security")
int BPF_PROG(telos_shm_free, struct kern_ipc_perm *shp) {
  __u32 id = BPF_CORE_READ(shp, id);
  bpf_map_delete_elem(&tainted_shmid_map, &id);
  return 0;
}
