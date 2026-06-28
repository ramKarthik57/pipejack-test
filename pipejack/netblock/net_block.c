#define AF_INET 2
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);   // destination IP (IPv4)
    __type(value, __u8);  // 1 = allowed
} allowed_ips SEC(".maps");

SEC("cgroup/connect4")
int block_connect(struct bpf_sock_addr *ctx) {
    if (ctx->user_family != AF_INET)
        return 1; // allow non-IPv4

    __u32 dst_ip = ctx->user_ip4;
    __u8 *allowed = bpf_map_lookup_elem(&allowed_ips, &dst_ip);
    if (allowed && *allowed == 1)
        return 1; // allow

    // Deny the connection
    return 0;
}

char _license[] SEC("license") = "GPL";
