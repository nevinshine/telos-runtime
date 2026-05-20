#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // IP address (network byte order)
    __type(value, __u8);  // 1 = blocked
} blocklist SEC(".maps");

SEC("xdp")
int hyperion_xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;

    // Check if destination or source IP is in the blocklist
    // XDP intercepts packets BEFORE the network stack, giving O(1) mitigation 
    // against C2/Exfiltration vectors identified by Telos Cortex Domain Intel
    __u8 *blocked = bpf_map_lookup_elem(&blocklist, &dst_ip);
    if (blocked && *blocked == 1) {
        return XDP_DROP;
    }
    
    __u8 *src_blocked = bpf_map_lookup_elem(&blocklist, &src_ip);
    if (src_blocked && *src_blocked == 1) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";