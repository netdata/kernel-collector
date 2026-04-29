#define KBUILD_MODNAME "dns_buffer_netdata"
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
#include "netdata_dns_buffer.h"

/************************************************************************************
 *
 *                                 MAPS Section
 *
 ***********************************************************************************/

NETDATA_BPF_RINGBUF_DEF(dns_events, NETDATA_DNS_RINGBUF_SIZE);

/*
 * Configurable set of DNS ports. User space populates this before attaching
 * the filter — the same design as dns_kern.c.
 */
NETDATA_BPF_HASH_DEF(dns_ports, __u16, __u8, 32);

/************************************************************************************
 *
 *                                Local Functions
 *
 ***********************************************************************************/

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

/*
 * Parse the L3 header, advance *offset past it, and fill saddr/daddr.
 * Returns the IP version (4 or 6) on success, 0 on failure.
 * saddr and daddr must each point to a 16-byte (4 x __u32) buffer.
 */
static __always_inline __u8 read_l3_info(struct __sk_buff *skb, __u64 *offset, __u16 l2_protocol,
                                          __u8 *transport_protocol,
                                          __u32 *saddr, __u32 *daddr)
{
    if (l2_protocol == ETH_P_IP) {
        struct iphdr iph = { };
        __u16 frag;

        if (bpf_skb_load_bytes(skb, *offset, &iph, sizeof(iph)) < 0)
            return 0;

        if (iph.ihl < 5)
            return 0;

        frag = bpf_ntohs(iph.frag_off);
        if (frag & 0x1FFF)  /* non-first fragments have no complete L4 header */
            return 0;

        *transport_protocol = iph.protocol;
        saddr[0] = iph.saddr;
        saddr[1] = saddr[2] = saddr[3] = 0;
        daddr[0] = iph.daddr;
        daddr[1] = daddr[2] = daddr[3] = 0;
        *offset += (__u64)iph.ihl * 4;
        return 4;

    } else if (l2_protocol == ETH_P_IPV6) {
        struct ipv6hdr ip6h = { };

        if (bpf_skb_load_bytes(skb, *offset, &ip6h, sizeof(ip6h)) < 0)
            return 0;

        *transport_protocol = ip6h.nexthdr;

        if (bpf_skb_load_bytes(skb, *offset + offsetof(struct ipv6hdr, saddr), saddr, 16) < 0)
            return 0;
        if (bpf_skb_load_bytes(skb, *offset + offsetof(struct ipv6hdr, daddr), daddr, 16) < 0)
            return 0;

        *offset += sizeof(ip6h);
        return 6;
    }

    return 0;
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

/************************************************************************************
 *
 *                                   Filter Section
 *
 ***********************************************************************************/

SEC("socket")
int socket__dns_filter_buffer(struct __sk_buff *skb)
{
    __u64 offset = 0;
    __u16 l2_protocol = 0;
    __u8  transport_protocol = 0;
    __u8  ip_version = 0;
    __u16 sport = 0, dport = 0;
    __u32 saddr[4], daddr[4];

    if (!read_l2_protocol(skb, &offset, &l2_protocol))
        return 0;

    ip_version = read_l3_info(skb, &offset, l2_protocol, &transport_protocol, saddr, daddr);
    if (!ip_version)
        return 0;

    if (!read_transport_ports(skb, offset, transport_protocol, &sport, &dport))
        return 0;

    /* Determine direction: query goes TO a DNS port, response comes FROM one. */
    __u8 is_query    = bpf_map_lookup_elem(&dns_ports, &dport) ? 1 : 0;
    __u8 is_response = (!is_query && bpf_map_lookup_elem(&dns_ports, &sport)) ? 1 : 0;

    if (!is_query && !is_response)
        return 0;

    struct netdata_dns_event_t *ev = bpf_ringbuf_reserve(&dns_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->ct         = bpf_ktime_get_ns();
    ev->saddr[0]   = saddr[0];
    ev->saddr[1]   = saddr[1];
    ev->saddr[2]   = saddr[2];
    ev->saddr[3]   = saddr[3];
    ev->daddr[0]   = daddr[0];
    ev->daddr[1]   = daddr[1];
    ev->daddr[2]   = daddr[2];
    ev->daddr[3]   = daddr[3];
    ev->pkt_len    = skb->len;
    ev->sport      = sport;
    ev->dport      = dport;
    ev->protocol   = transport_protocol;
    ev->ip_version = ip_version;
    ev->direction  = is_query ? NETDATA_DNS_QUERY : NETDATA_DNS_RESPONSE;
    ev->pad        = 0;

    bpf_ringbuf_submit(ev, 0);

    /*
     * Return 0 (drop) — user space reads structured events from the ring buffer
     * and no longer needs raw packet delivery via the socket.
     */
    return 0;
}

char _license[] SEC("license") = "GPL";
