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

#define MAX_ENTRIES 65535
#define IDPS_MARK 0x123

// Map containing original four-tuple of a proxied tcp packet.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct __network_layer_packet);
    __type(value, struct __network_layer_packet);
} original_network_packets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct __destination_interfaces);
} redirect_interface_destination SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} incoming_packets_perf_buffer SEC(".maps");

// Stores the interface destination for rerouting packets in the host.
struct __destination_interfaces {
    // The index of the default interface for network traffic (usually eth0)
    __u32 default_iface_idx;
    // The index of the idps interface (usually idps0)
    __u32 ingress_idps_idx;
};

// Stores a four-tuple representing a packet routed inside the firewall.
struct __network_layer_packet {
	__u16 sport;
	__u16 dport;
	__u32 saddr;
	__u32 daddr;
};

SEC("tc")
int redirect_marked_traffic(struct __sk_buff *skb) {
     __u32 default_key = 0;
    struct __destination_interfaces *dest = bpf_map_lookup_elem(&redirect_interface_destination, &default_key);
    if (!dest) 
        return TC_ACT_OK;
    
    // zero flag means that the socket buffer is
    // redirected to the iface egress path.
    skb->mark = IDPS_MARK;
    return bpf_redirect(dest->default_iface_idx, 0);
}

SEC("tc")
int redirect_to_idps(struct __sk_buff *skb) {
    __u32 dest_port = 0;
    __u32 source_port = 0;
    __u32 default_key = 0;
    __u32 zero = 0;

    // Get the redirect destination.
    struct __destination_interfaces *dest = bpf_map_lookup_elem(&redirect_interface_destination, &default_key);
    if (!dest) 
        return TC_ACT_OK;

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
    if (proto != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    struct tcphdr *tcp_header = (void*)ip_header + sizeof(struct iphdr);
    if ((void*) tcp_header + sizeof(struct tcphdr) > data_end) {
        return TC_ACT_OK;
    }

    dest_port = tcp_header->dest;
    source_port = tcp_header->source;

    if (skb->mark != IDPS_MARK) {
        // Log packet forwarded to idps for logging.
        struct __network_layer_packet packet = {};
        packet.daddr = ip_header->daddr;
        packet.saddr = ip_header->saddr;
        packet.sport = source_port;
        packet.dport = dest_port;
        bpf_perf_event_output(skb, &incoming_packets_perf_buffer, BPF_F_CURRENT_CPU, &packet, sizeof(struct __network_layer_packet));

        // Query if the original packet of a proxies packet exists in memory.
        struct __network_layer_packet *original_packet = bpf_map_lookup_elem(&original_network_packets, &packet);
        if (original_packet != NULL) {
            ip_header->daddr = original_packet->daddr;
            ip_header->saddr = original_packet->saddr;
            tcp_header->source = original_packet->sport;
            tcp_header->dest = original_packet->dport;
        }

        // zero flag means that the socket buffer is
        // redirected to the iface egress path.
        return bpf_clone_redirect(skb, dest->ingress_idps_idx, 0);
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";