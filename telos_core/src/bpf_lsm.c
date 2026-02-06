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
#include "../../shared/common_maps.h"

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
  __u32 pid;
  __u32 taint_level;
  __u32 blocked;
  char comm[16];
  char action[16]; // "execve" or "open"
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024); // 256 KB
} events SEC(".maps");

// === HELPER FUNCTIONS ===

static __always_inline struct telos_config_t *get_config(void) {
  __u32 key = 0;
  return bpf_map_lookup_elem(&config_map, &key);
}

static __always_inline void emit_event(__u32 pid, __u32 taint, __u32 blocked,
                                       const char *action) {
  struct event_t *event;

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event)
    return;

  event->pid = pid;
  event->taint_level = taint;
  event->blocked = blocked;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  // Copy action string (max 15 chars + null)
  __builtin_memcpy(event->action, action, 7);

  bpf_ringbuf_submit(event, 0);
}

// === LSM HOOKS ===

/*
 * Hook: bprm_check_security
 *
 * Called before execve() is allowed to proceed.
 * This is the primary enforcement point - if a tainted process
 * tries to spawn a new program (e.g., curl, bash), we block it.
 *
 * IMPORTANT: We also check the PARENT's taint level, because when a
 * tainted process forks and execs, the child has a new PID that isn't
 * in our map yet, but we should still block it.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(telos_check_exec, struct linux_binprm *bprm) {
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct process_info_t *info = NULL;
  __u32 effective_taint = TAINT_CLEAN;

  // Get config
  struct telos_config_t *config = get_config();
  __u32 max_taint = config ? config->max_taint_for_exec : TAINT_MEDIUM;
  __u32 enforce = config ? config->enabled : 1;

  // First, check if THIS process is tracked
  info = bpf_map_lookup_elem(&process_map, &pid);
  if (info) {
    effective_taint = info->taint_level;
  } else {
    // Not tracked directly - check PARENT process
    // This catches forked children of tainted processes
    struct task_struct *current_task =
        (struct task_struct *)bpf_get_current_task();
    if (current_task) {
      // Get parent's PID
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
    // Emit to ringbuf for userspace logging (lightweight)
    emit_event(pid, effective_taint, 1, "execve");

    if (enforce) {
      return -EPERM; // Permission denied
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

  // Lookup process in taint map
  struct process_info_t *info = bpf_map_lookup_elem(&process_map, &pid);
  if (!info) {
    // Not a tracked process - allow
    return 0;
  }

  // Get config
  struct telos_config_t *config = get_config();
  __u32 max_taint = config ? config->max_taint_for_open : TAINT_HIGH;
  __u32 enforce = config ? config->enabled : 1;

  // For now, we only block if taint is CRITICAL
  // More granular file path checking would require more complex logic
  if (info->taint_level >= TAINT_CRITICAL) {
    // Get the dentry to check path
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
      return 0;

    // Read filename (limited capability in BPF)
    char filename[32];
    int ret = bpf_probe_read_kernel_str(&filename, sizeof(filename),
                                        BPF_CORE_READ(dentry, d_name.name));
    if (ret < 0)
      return 0;

    // Check for sensitive file patterns
    // Note: This is a simplified check - real implementation would use
    // a map of blocked paths

    // Check for SSH keys
    if (filename[0] == 'i' && filename[1] == 'd' && filename[2] == '_') {
      // Matches id_* (id_rsa, id_ed25519, etc.)
      emit_event(pid, info->taint_level, 1, "open");

      if (enforce) {
        return -EPERM;
      }
    }
  }

  return 0; // Allow
}

/*
 * Hook: task_alloc (optional)
 *
 * Track process creation to propagate taint to child processes.
 * If a tainted process forks, the child inherits the taint.
 */
SEC("lsm/task_alloc")
int BPF_PROG(telos_task_alloc, struct task_struct *task,
             unsigned long clone_flags) {
  __u32 parent_pid = bpf_get_current_pid_tgid() >> 32;

  // Check if parent is tainted
  struct process_info_t *parent_info =
      bpf_map_lookup_elem(&process_map, &parent_pid);
  if (!parent_info) {
    return 0; // Parent not tracked
  }

  // If parent is tainted, log via ringbuf (not bpf_printk)
  // The actual blocking happens in bprm_check_security via parent check

  return 0; // Always allow fork (blocking happens at execve)
}
