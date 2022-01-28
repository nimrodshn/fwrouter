#include <linux/bpf.h>
#include "bpf_helpers.h"

#define MAX_NODES 256

struct dest_info {
    __u32 saddr;
    __u32 daddr;
    __u8 dmac[6];
    __u16 ifindex;
};

// A maps of "nodes" (interfaces) used to route https traffic.
struct bpf_map_def SEC("maps") https_nodes = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct dest_info),
    .max_entries = MAX_NODES,
};

SEC("xdp")
int router(struct xdp_md *ctx) {
    bpf_printk("Got here.\n");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
