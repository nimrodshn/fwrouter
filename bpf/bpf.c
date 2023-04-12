#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stdio.h>
#include "bpf_helpers.h"

#define MAX_NODES 256

enum condition_type {
    L7_PROTOCOL_HTTPS,
    MARK,
    DEFAULT
};

struct __condition {
    enum condition_type type;
    __u32 value;
};

// Represents the information required to compute the next transition.
struct __transition {
    struct __condition cond;
    __u32 mark;
    __u32 next_iface_idx;
};

struct bpf_map_def SEC("maps") transitions = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct __transition),
    .max_entries = MAX_NODES,
};

// To differentiate between "regular" transitions and the default one we keep a separate map just for the default transition.
struct bpf_map_def SEC("maps") default_transition = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct __transition),
    .max_entries = 1,
};

// There is no simple way or interface to get the number of elements in a map from the kernel so the user space has to report it.
struct bpf_map_def SEC("maps") transitions_len = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;
	struct ethhdr *eth = data;

	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_SHOT;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(struct iphdr) > data_end)
        return TC_ACT_SHOT;
    
    __u32 default_key = 0;
    struct __transition *default_destination = bpf_map_lookup_elem(&default_transition, &default_key);
    if ( default_destination != NULL ) {
        bpf_printk("Routing traffic to interface: %d\n", default_destination->next_iface_idx);
        return bpf_clone_redirect(skb, default_destination->next_iface_idx, BPF_F_INGRESS);    
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";