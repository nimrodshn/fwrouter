#include <linux/bpf.h>
#include <linux/pkt_cls.h>
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

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb)
{
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
