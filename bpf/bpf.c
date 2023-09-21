#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stdio.h>
#include <string.h>
#include "bpf_helpers.h"

#define MAX_NODES 256
#define MAX_TRANSITIONS 10

enum condition_type {
    L7_PROTOCOL_HTTPS,
    MARK,
    DEFAULT
};

enum __queue {
    INGRESS,
    EGRESS
};

struct __condition {
    enum condition_type type;
    __u32 value;
};

// Represents the information required to compute the next transition.
struct __transition {
    struct __condition cond;
    enum __queue queue;
    __u32 next_iface_idx;
};

struct bpf_map_def SEC("maps") ingress_transitions = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct __transition),
    .max_entries = MAX_NODES,
};

struct bpf_map_def SEC("maps") egress_transitions = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct __transition),
    .max_entries = MAX_NODES,
};

SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    __u32 default_key = 0;
    void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;
	struct ethhdr *eth = data;

	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_SHOT;
    
    struct __transition *destination = bpf_map_lookup_elem(&ingress_transitions, &default_key);
    if ( destination != NULL ) {
        bpf_printk("Got hereeee %d %d %d\n", destination->cond.type, destination->cond.value, destination->next_iface_idx);
        switch (destination->cond.type) {
            case MARK:
                bpf_printk("MARK condition: %d\n", destination->cond.value);
                bpf_printk("MARK skb->mark: %d\n", skb->mark);
                if (skb->mark == destination->cond.value) {
                    bpf_printk("MARK MATCHED!!!!!!!!!!\n");
                    switch (destination->queue) {
                        case INGRESS:
                            return bpf_clone_redirect(skb, destination->next_iface_idx, BPF_F_INGRESS);
                        case EGRESS:
                            // zero flag means that the socket buffer is
                            // redirected to the iface egress path
                            return bpf_clone_redirect(skb, destination->next_iface_idx, 0);
                        }
                }
                break;
            case L7_PROTOCOL_HTTPS:
                break;
            case DEFAULT:
                break;
        }
    }

    return TC_ACT_OK;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    __u32 default_key = 0;
    void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;
	struct ethhdr *eth = data;

	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_SHOT;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(struct iphdr) > data_end)
        return TC_ACT_SHOT;
    
    struct __transition *destination = bpf_map_lookup_elem(&egress_transitions, &default_key);
    if ( destination != NULL ) {
        bpf_printk("Got hereeee %d %d %d\n", destination->cond.type, destination->cond.value, destination->next_iface_idx);
        switch (destination->cond.type) {
            case MARK:
                bpf_printk("MARK condition: %d\n", destination->cond.value);
                bpf_printk("MARK skb->mark: %d\n", skb->mark);
                if (skb->mark == destination->cond.value) {
                    bpf_printk("MARK MATCHED!!!!!!!!!!\n");
                    switch (destination->queue) {
                        case INGRESS:
                            return bpf_clone_redirect(skb, destination->next_iface_idx, BPF_F_INGRESS);
                        case EGRESS:
                            // zero flag means that the socket buffer is
                            // redirected to the iface egress path
                            return bpf_clone_redirect(skb, destination->next_iface_idx, 0);
                        }
                }
                break;
            case L7_PROTOCOL_HTTPS:
                break;
            case DEFAULT:
                break;
        }
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";