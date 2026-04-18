#define KBUILD_MODNAME "dns_netdata"
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "netdata_common.h"

NETDATA_BPF_HASH_DEF(dns_ports, __u16, __u8, 32);

static __always_inline int read_l2_protocol(struct __sk_buff *skb, __u64 *offset, __u16 *protocol)
{
    struct ethhdr eth = { };

    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return 0;

    *offset = sizeof(eth);
    *protocol = bpf_ntohs(eth.h_proto);

    if (*protocol == ETH_P_8021Q || *protocol == ETH_P_8021AD) {
        struct vlan_hdr vlan = { };

        if (bpf_skb_load_bytes(skb, *offset, &vlan, sizeof(vlan)) < 0)
            return 0;

        *offset += sizeof(vlan);
        *protocol = bpf_ntohs(vlan.h_vlan_encapsulated_proto);
    }

    return 1;
}

static __always_inline int read_transport_ports(struct __sk_buff *skb, __u64 offset, __u8 protocol,
                                                __u16 *sport, __u16 *dport)
{
    if (protocol == IPPROTO_UDP) {
        struct udphdr udp = { };

        if (bpf_skb_load_bytes(skb, offset, &udp, sizeof(udp)) < 0)
            return 0;

        *sport = bpf_ntohs(udp.source);
        *dport = bpf_ntohs(udp.dest);
        return 1;
    }

    if (protocol == IPPROTO_TCP) {
        struct tcphdr tcp = { };

        if (bpf_skb_load_bytes(skb, offset, &tcp, sizeof(tcp)) < 0)
            return 0;

        *sport = bpf_ntohs(tcp.source);
        *dport = bpf_ntohs(tcp.dest);
        return 1;
    }

    return 0;
}

SEC("socket")
int socket__dns_filter(struct __sk_buff *skb)
{
    __u64 offset = 0;
    __u16 l2_protocol = 0;
    __u8 transport_protocol = 0;
    __u16 sport = 0;
    __u16 dport = 0;

    if (!read_l2_protocol(skb, &offset, &l2_protocol))
        return 0;

    if (l2_protocol == ETH_P_IP) {
        struct iphdr iph = { };
        __u16 frag = 0;

        if (bpf_skb_load_bytes(skb, offset, &iph, sizeof(iph)) < 0)
            return 0;

        if (iph.ihl < 5)
            return 0;

        frag = bpf_ntohs(iph.frag_off);
        if (frag & 0x1FFF)
            return 0;

        transport_protocol = iph.protocol;
        offset += (__u64)iph.ihl * 4;
    } else if (l2_protocol == ETH_P_IPV6) {
        struct ipv6hdr ip6h = { };

        if (bpf_skb_load_bytes(skb, offset, &ip6h, sizeof(ip6h)) < 0)
            return 0;

        transport_protocol = ip6h.nexthdr;
        offset += sizeof(ip6h);
    } else {
        return 0;
    }

    if (!read_transport_ports(skb, offset, transport_protocol, &sport, &dport))
        return 0;

    if (bpf_map_lookup_elem(&dns_ports, &sport) || bpf_map_lookup_elem(&dns_ports, &dport))
        return -1;

    return 0;
}

char _license[] SEC("license") = "GPL";
