// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_DNS_BUFFER_H_
#define _NETDATA_DNS_BUFFER_H_ 1

#define NETDATA_DNS_RINGBUF_SIZE (1 << 20)

enum netdata_dns_event_direction {
    NETDATA_DNS_QUERY    = 0,   /* packet destined for a DNS port */
    NETDATA_DNS_RESPONSE = 1,   /* packet originating from a DNS port */
};

/*
 * saddr/daddr layout matches union netdata_ip.addr32:
 *   IPv4 — addr in [0], [1..3] = 0
 *   IPv6 — full 128-bit address across all four slots
 */
struct netdata_dns_event_t {
    __u64 ct;           /* bpf_ktime_get_ns() at capture time */
    __u32 saddr[4];     /* source IP */
    __u32 daddr[4];     /* destination IP */
    __u32 pkt_len;      /* skb->len in bytes */
    __u16 sport;        /* source port (host byte order) */
    __u16 dport;        /* destination port (host byte order) */
    __u8  protocol;     /* IPPROTO_UDP or IPPROTO_TCP */
    __u8  ip_version;   /* 4 or 6 */
    __u8  direction;    /* netdata_dns_event_direction */
    __u8  pad;
};

#endif /* _NETDATA_DNS_BUFFER_H_ */
