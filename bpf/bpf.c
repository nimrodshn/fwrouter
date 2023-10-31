#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stdio.h>
#include <string.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

#define MAX_ENTRIES
#define IDPS_MARK 0x123

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct __destination);
} default_destination SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
}  incoming_packets_perf_buffer SEC(".maps");

// Stores the mapping from a port range to the next assigned socket.
struct __mapping {
    __u32 low_port;
    __u32 high_port;
};

struct __destination {
    __u32 default_iface_idx;
    __u32 ingress_idps_idx;
};

struct app_event {
	__u16 sport;
	__u16 dport;
	__u32 saddr;
	__u32 daddr;
};

SEC("tc")
int redirect_marked_traffic(struct __sk_buff *skb) {
     __u32 default_key = 0;
     struct __destination *dest = bpf_map_lookup_elem(&default_destination, &default_key);
    if (dest != NULL) {
        // zero flag means that the socket buffer is
        // redirected to the iface egress path.
        skb->mark = IDPS_MARK;
        return bpf_redirect(dest->default_iface_idx, 0);
    }
    return TC_ACT_OK;
}

SEC("tc")
int redirect_to_idps(struct __sk_buff *skb) {
    __u32 dest_port = 0;
    __u32 source_port = 0;
    __u32 default_key = 0;
    __u32 zero = 0;

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    // Necessary validation: if L3 layer does not exist, ignore and continue.
    if (data + sizeof(struct ethhdr) > data_end) {
        return TC_ACT_OK;
    }

    struct ethhdr *eth = data;
    struct iphdr *ip_header = data + sizeof(struct ethhdr);
    if ((void*) ip_header + sizeof(struct iphdr) > data_end) {
        return TC_ACT_OK;
    }

    __u8 proto = ip_header->protocol;
    if (proto == IPPROTO_UDP) {
        return TC_ACT_OK;
    }

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (void*)ip_header + sizeof(struct iphdr);
        if ((void*) tcp_header + sizeof(struct tcphdr) > data_end) {
            return TC_ACT_OK;
        }
    
        dest_port = tcp_header->dest;
        source_port = tcp_header->source;
    }

    if (skb->mark != IDPS_MARK) {
        struct __destination *dest = bpf_map_lookup_elem(&default_destination, &default_key);
        if (dest != NULL) {
            struct app_event event = {};
            event.daddr = ip_header->daddr;
            event.saddr = ip_header->saddr;
            event.sport = source_port;
            event.dport = dest_port;
            bpf_perf_event_output(skb, &incoming_packets_perf_buffer, BPF_F_CURRENT_CPU, &event, sizeof(struct app_event));

            // zero flag means that the socket buffer is
            // redirected to the iface egress path.
            return bpf_clone_redirect(skb, dest->ingress_idps_idx, 0);
        }
        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";