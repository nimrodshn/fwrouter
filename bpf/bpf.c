#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stdio.h>
#include "bpf_helpers.h"

#define MAX_NODES 256

const int IPV4_ALEN = 4;
const int KEY_SIZE = sizeof(unsigned int) + IPV4_ALEN + 1;

// A maps of interfaces used to route https traffic.
struct bpf_map_def SEC("maps") route_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = KEY_SIZE,
    .value_size = sizeof(unsigned int),
    .max_entries = MAX_NODES,
};

struct bpf_map_def SEC("maps") tx_port = {
    .type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(unsigned int),
    .max_entries = MAX_NODES,
};

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb)
{
    void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;
	struct ethhdr *eth = data;

	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_SHOT;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(struct iphdr) > data_end)
        return TC_ACT_SHOT;
    
    char key [KEY_SIZE];
    snprintf(key, KEY_SIZE, "%d%d", ip->saddr, skb->ifindex);

    int *ifidx = bpf_map_lookup_elem(&route_map, &key);
    if (ifidx) {
        return bpf_redirect_map(&tx_port, *ifidx, 0);    
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";