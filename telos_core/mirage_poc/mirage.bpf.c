// go:build ignore
//   +build ignore

#include "../src/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

const volatile int target_pid = 0;
const volatile int target_fd = 0;

// State to pass from entry to exit
struct active_read_t {
  __u64 user_buf; // Changed from void* to __u64 for Go compatibility
  size_t requested_count;
};

// Map to track active sys_reads
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32); // PID/TID
  __type(value, struct active_read_t);
} active_reads SEC(".maps");

/*
 * 1. ENTRY HOOK
 * Capture the user buffer pointer before the read happens.
 * Hooking ksys_read avoids the syscall wrappers on x86_64, letting us safely
 * parse arguments without unsafe pointer dereferences.
 */
SEC("kprobe/ksys_read")
int BPF_KPROBE(mirage_sys_read_enter, unsigned int fd, char *buf,
               size_t count) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;

  if (target_pid != 0 && pid != target_pid)
    return 0;

  if ((int)fd != target_fd)
    return 0;

  struct active_read_t state = {};
  state.user_buf = (__u64)buf;
  state.requested_count = count;

  // Save state for the kretprobe
  bpf_map_update_elem(&active_reads, &pid_tgid, &state, BPF_ANY);

  return 0;
}

/*
 * 2. EXIT HOOK
 * The kernel has read the file. Overwrite the buffer before returning to
 * userspace.
 */
SEC("kretprobe/ksys_read")
int BPF_KRETPROBE(mirage_sys_read_exit) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();

  // Look up our state
  struct active_read_t *state = bpf_map_lookup_elem(&active_reads, &pid_tgid);
  if (!state)
    return 0; // Not our target read

  // Get actual bytes read by the kernel
  long bytes_read = PT_REGS_RC(ctx);

  if (bytes_read > 0) {
    char honey[] = "[MIRAGE] - HONEY TOKEN INJECTED SUCCESSFULLY\n";
    long honey_len = sizeof(honey) - 1;

    // CRITICAL SAFETY CHECK:
    // Do not write more bytes than the kernel actually read,
    // to prevent corrupting adjacent user memory or causing a page fault.
    long write_len = honey_len;
    if (write_len > bytes_read) {
      write_len = bytes_read; // Truncate token if real file is too small
    }

    // BPF Verifier requires bounded values.
    if (write_len > 0 && write_len <= sizeof(honey)) {
      long err =
          bpf_probe_write_user((void *)state->user_buf, honey, write_len);
      if (err == 0) {
        bpf_printk("MIRAGE: Overwrote %ld bytes in user buffer", write_len);
      } else {
        bpf_printk("MIRAGE: bpf_probe_write_user failed: %ld", err);
      }
    }
  }

  // Cleanup map
  bpf_map_delete_elem(&active_reads, &pid_tgid);
  return 0;
}
