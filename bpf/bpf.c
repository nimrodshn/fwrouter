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

#define IP_SRC_OFF ETH_ALEN + offsetof(struct iphdr, saddr)
#define IP_DST_OFF ETH_ALEN + offsetof(struct iphdr, daddr)
#define TCP_SRC_OFF ETH_ALEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source)
#define TCP_DST_OFF ETH_ALEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct __network_layer_tuple);
    __type(value, struct __network_layer_tuple);
} proxy_to_orig_inbound_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct __network_layer_tuple);
    __type(value, struct __network_layer_tuple);
} proxy_to_orig_outbound_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct __network_layer_tuple);
    __type(value, struct __network_layer_tuple);
} orig_to_proxy_outbound_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct __network_layer_tuple);
    __type(value, struct __network_layer_tuple);
} orig_to_proxy_inbound_map SEC(".maps");

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
struct __network_layer_tuple {
	__u16 sport;
	__u16 dport;
	__u32 saddr;
	__u32 daddr;
};

SEC("tc")
int redirect_marked_traffic(struct __sk_buff *skb) {
    struct __network_layer_tuple *proxied_packet;
     __u32 default_key = 0;
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

    // Use the original packet as key to find the proxied packet to pass back to the original sender.
    struct __network_layer_tuple original_context_key = {};
    original_context_key.saddr = ip_header->saddr;
    original_context_key.daddr = ip_header->daddr;
    original_context_key.sport = tcp_header->source;
    original_context_key.dport = tcp_header->dest;

    // Check if the packet is part of a of a proxied request-response cycle.
    // Check for inbound packets.
    proxied_packet = bpf_map_lookup_elem(&orig_to_proxy_inbound_map, &original_context_key);
    if (proxied_packet != NULL) {
        bpf_skb_store_bytes(skb, IP_SRC_OFF, &proxied_packet->saddr, sizeof(proxied_packet->saddr), BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH);
        bpf_skb_store_bytes(skb, IP_DST_OFF, &proxied_packet->daddr, sizeof(proxied_packet->daddr), BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH);
        bpf_skb_store_bytes(skb, TCP_SRC_OFF, &proxied_packet->sport, sizeof(proxied_packet->sport), BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH);
        bpf_skb_store_bytes(skb, TCP_DST_OFF, &proxied_packet->dport, sizeof(proxied_packet->dport), BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH);
    }

    // Check for outbound packets.
    proxied_packet = bpf_map_lookup_elem(&orig_to_proxy_outbound_map, &original_context_key);
    if (proxied_packet != NULL) {
        bpf_skb_store_bytes(skb, IP_SRC_OFF, &proxied_packet->saddr, sizeof(proxied_packet->saddr), BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH);
        bpf_skb_store_bytes(skb, IP_DST_OFF, &proxied_packet->daddr, sizeof(proxied_packet->daddr), BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH);
        bpf_skb_store_bytes(skb, TCP_SRC_OFF, &proxied_packet->sport, sizeof(proxied_packet->sport), BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH);
        bpf_skb_store_bytes(skb, TCP_DST_OFF, &proxied_packet->dport, sizeof(proxied_packet->dport), BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH);
    }

    // zero flag means that the socket buffer is
    // redirected to the iface egress path.
    // Mark the packets as finished with the IDPS.
    skb->mark = IDPS_MARK;
    return bpf_redirect(dest->default_iface_idx, BPF_F_INGRESS);
}

SEC("tc")
int redirect_to_idps_ingress(struct __sk_buff *skb) {
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
        struct __network_layer_tuple original_context_key = {};
        struct __network_layer_tuple packet = {};
        
        packet.saddr = ip_header->saddr;
        packet.daddr = ip_header->daddr;
        packet.sport = source_port;
        packet.dport = dest_port;
        // Log packet forwarded to idps for logging.
        bpf_perf_event_output(skb, &incoming_packets_perf_buffer, BPF_F_CURRENT_CPU, &packet, sizeof(struct __network_layer_tuple));

        original_context_key.daddr = packet.daddr;
        original_context_key.saddr = packet.saddr;
        original_context_key.dport = packet.dport;
        original_context_key.sport = packet.sport;

        // Query if the original packet exists in memory.
        struct __network_layer_tuple *original_packet = bpf_map_lookup_elem(&proxy_to_orig_inbound_map, &original_context_key);
        if (original_packet != NULL) {
            // Write the proxied four-tuple to the packet.
            bpf_skb_store_bytes(skb, IP_SRC_OFF, &original_packet->saddr, sizeof(original_packet->saddr), BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH);
            bpf_skb_store_bytes(skb, IP_DST_OFF, &original_packet->daddr, sizeof(original_packet->daddr), BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH);
            bpf_skb_store_bytes(skb, TCP_SRC_OFF, &original_packet->sport, sizeof(original_packet->sport), BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH);
            bpf_skb_store_bytes(skb, TCP_DST_OFF, &original_packet->dport, sizeof(original_packet->dport), BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH);
        }

        return bpf_clone_redirect(skb, dest->ingress_idps_idx, BPF_F_INGRESS);
    }

    return TC_ACT_OK;
}

SEC("tc")
int redirect_to_idps_egress(struct __sk_buff *skb) {
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
        struct __network_layer_tuple original_context_key = {};
        struct __network_layer_tuple packet = {};
        
        packet.saddr = ip_header->saddr;
        packet.daddr = ip_header->daddr;
        packet.sport = source_port;
        packet.dport = dest_port;
        // Log packet forwarded to idps for logging.
        bpf_perf_event_output(skb, &incoming_packets_perf_buffer, BPF_F_CURRENT_CPU, &packet, sizeof(struct __network_layer_tuple));

        original_context_key.saddr = packet.saddr;
        original_context_key.daddr = packet.daddr;
        original_context_key.sport = packet.sport;
        original_context_key.dport = packet.dport;

        // Query if the original packet exists in memory.
        struct __network_layer_tuple *original_packet = bpf_map_lookup_elem(&proxy_to_orig_outbound_map, &original_context_key);
        if (original_packet != NULL) {
            // Write the proxied four-tuple to the packet.
            bpf_skb_store_bytes(skb, IP_SRC_OFF, &original_packet->saddr, sizeof(original_packet->saddr), BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH);
            bpf_skb_store_bytes(skb, IP_DST_OFF, &original_packet->daddr, sizeof(original_packet->daddr), BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH);
            bpf_skb_store_bytes(skb, TCP_SRC_OFF, &original_packet->sport, sizeof(original_packet->sport), BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH);
            bpf_skb_store_bytes(skb, TCP_DST_OFF, &original_packet->dport, sizeof(original_packet->dport), BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH);
        }

        return bpf_clone_redirect(skb, dest->ingress_idps_idx, BPF_F_INGRESS);
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";