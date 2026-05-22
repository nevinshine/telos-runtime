// go:build ignore

/*
 * Telos Core - BPF Map Definitions
 *
 * Shared map definitions for the eBPF program.
 * This header is included by bpf_lsm.c.
 */

#ifndef __PROCESS_MAP_H
#define __PROCESS_MAP_H

#include "../../shared/common_maps.h"

/*
 * Map pinning paths
 *
 * Maps are pinned to the BPF filesystem for persistence
 * and access from userspace (Go loader).
 */
#define TELOS_BPF_PATH "/sys/fs/bpf/telos"
#define PROCESS_MAP_PATH TELOS_BPF_PATH "/process_map"
#define CONFIG_MAP_PATH TELOS_BPF_PATH "/config_map"
#define EVENTS_MAP_PATH TELOS_BPF_PATH "/events"
#define INODE_MAP_PATH TELOS_BPF_PATH "/inode_map"
#define NETWORK_MAP_PATH TELOS_BPF_PATH "/network_map"
#define EXEC_POLICY_MAP_PATH TELOS_BPF_PATH "/exec_policy_map"
#define TAINTED_MMAP_MAP_PATH TELOS_BPF_PATH "/tainted_mmap_map"
#define TAINTED_SHMID_MAP_PATH TELOS_BPF_PATH "/tainted_shmid_map"

/*
 * Inode sensitivity levels
 * 0 = Clean (Default)
 * 1 = Sensitive (e.g. config files)
 * 2 = Critical (e.g. SSH keys, shadow)
 */
struct inode_policy_t {
  __u32 sensitivity;
  __u32 reserved;
};

/*
 * Network Policy
 * Simple ALLOW/DENY for IP ranges or specific ports.
 * For M2, we implement a simple "Allowed IP" list.
 *
 * Key: __u32 (IPv4 Address)
 * Value: __u32 (1 = Allowed)
 */
struct network_policy_t {
  __u32 allowed;
};

/*
 * Execution Policy (Phase 5)
 * Enforces strictly allowed binaries for a specific PID based on intent.
 * mode: 0 = Unrestricted (fallback to taint), 1 = Allowlist enforced
 * expires_ns: Timestamp for TTL expiration (Future implementation)
 * allowed_bins: Up to 8 binary names (16 chars each, TASK_COMM_LEN)
 */
struct exec_policy_t {
  __u32 mode;
  __u64 expires_ns;
  __u8 allowed_bins[8][16];
};

#endif // __PROCESS_MAP_H
