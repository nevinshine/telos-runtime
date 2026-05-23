#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} gva_leak_map SEC(".maps");

SEC("kprobe/bpf_map_update_value")
int leak_any_map(struct pt_regs *ctx) {
    void *map_ptr = (void *)PT_REGS_PARM1(ctx);
    __u32 key = 0;
    __u64 gva = (__u64)map_ptr;
    bpf_map_update_elem(&gva_leak_map, &key, &gva, BPF_ANY);
    return 0;
}
