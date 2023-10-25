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

// Stores the mapping from a port range to the next assigned socket.
struct __mapping {
    __u32 low_port;
    __u32 high_port;
};

struct bpf_map_def SEC("maps") port_mappings = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct __mapping),
    .max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") default_socket = {
    .type = BPF_MAP_TYPE_SOCKMAP,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

SEC("tc")
int redir_lookup(struct __sk_buff *skb)
{
    __u32 dest_port = 0;
    __u32 default_key = 0;

    struct __mapping *mapping = bpf_map_lookup_elem(&port_mappings, &default_key);
    if ( mapping == NULL ) {
        return TC_ACT_OK;;
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
        struct udphdr *udp_header = (void*)ip_header + sizeof(struct iphdr);
        if ((void*) udp_header + sizeof(struct udphdr) > data_end) {
            return TC_ACT_OK;
        }
        
        dest_port = udp_header->dest;
    }

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (void*)ip_header + sizeof(struct iphdr);
        if ((void*) tcp_header + sizeof(struct tcphdr) > data_end) {
            return TC_ACT_OK;
        }
    
        dest_port = tcp_header->dest;
    }

    if (dest_port >= mapping->low_port && dest_port <= mapping->high_port) {
        struct bpf_sock *sk = bpf_map_lookup_elem(&default_socket, &default_key);
        if (!sk)
            return TC_ACT_OK;

        int err = bpf_sk_assign(skb, sk, 0);
        bpf_sk_release(sk);
        return err ? TC_ACT_SHOT : TC_ACT_OK;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";