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

#define MAX_ENTRIES 256
#define IDPS_MARK 0x123

// Stores the mapping from a port range to the next assigned socket.
struct __mapping {
    __u32 low_port;
    __u32 high_port;
};

struct __destination {
    __u32 default_iface_idx;
    __u32 ingress_idps_idx;
};

struct bpf_map_def SEC("maps") port_mappings = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct __mapping),
    .max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") default_destination = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(struct __destination),
    .value_size = sizeof(__u32),
    .max_entries = 1,
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
    __u32 default_key = 0;

    struct __mapping *mapping = bpf_map_lookup_elem(&port_mappings, &default_key);
    if ( mapping == NULL ) {
        return TC_ACT_OK;
    }

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
    }

    if (dest_port >= mapping->low_port && dest_port <= mapping->high_port && skb->mark != IDPS_MARK) {
        struct __destination *dest = bpf_map_lookup_elem(&default_destination, &default_key);
        if (dest != NULL) {
            // zero flag means that the socket buffer is
            // redirected to the iface egress path.
            return bpf_redirect(dest->ingress_idps_idx, 0);
        }
        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";