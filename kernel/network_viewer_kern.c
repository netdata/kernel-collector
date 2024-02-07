#define KBUILD_MODNAME "socket_netdata"
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_vlan.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "netdata_ebpf.h"

/************************************************************************************
 *
 *                              Hash Table Section
 *
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, netdata_nv_idx_t);
    __type(value, netdata_nv_data_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} tbl_nv_socket SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} nv_ctrl SEC(".maps");

#else
struct bpf_map_def SEC("maps") tbl_nd_socket = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(netdata_nv_idx_t),
    .value_size = sizeof(netdata_nv_data_t),
    .max_entries =  PID_MAX_DEFAULT,
};

struct bpf_map_def SEC("maps") nv_ctrl = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_CONTROLLER_END
};
#endif

/************************************************************************************
 *
 *                                 Common Section
 *
 ***********************************************************************************/

static __always_inline __u16 set_idx_value(netdata_nv_idx_t *nsi, struct inet_sock *is)
{
    __u16 family;

    // Read Family
    bpf_probe_read(&family, sizeof(u16), &is->sk.__sk_common.skc_family);
    // Read source and destination IPs
    if ( family == AF_INET ) { //AF_INET
        // bpf_probe_read(&nsi->saddr.addr32[0], sizeof(u32), &is->inet_rcv_saddr); // bind to local address
        bpf_probe_read(&nsi->saddr.ipv4, sizeof(u32), &is->inet_saddr);
        bpf_probe_read(&nsi->daddr.ipv4, sizeof(u32), &is->inet_daddr);
        if (nsi->saddr.ipv4 == 0 || nsi->daddr.ipv4 == 0) // Zero
            return AF_UNSPEC;
    }
    // Check necessary according https://elixir.bootlin.com/linux/v5.6.14/source/include/net/sock.h#L199
    else if ( family == AF_INET6 ) {
        // struct in6_addr *addr6 = &is->sk.sk_v6_rcv_saddr; // bind to local address
        struct in6_addr *addr6 = &is->sk.__sk_common.skc_v6_rcv_saddr.s6_addr;
        bpf_probe_read(&nsi->saddr.ipv6.addr8,  sizeof(__u8)*16, &addr6->s6_addr);

        addr6 = &is->sk.__sk_common.skc_v6_daddr.s6_addr;
        bpf_probe_read(&nsi->daddr.ipv6.addr8,  sizeof(__u8)*16, &addr6->s6_addr);

        if (((nsi->saddr.ipv6.addr64[0] == 0) && (nsi->saddr.ipv6.addr64[1] == 0)) ||
            ((nsi->daddr.ipv6.addr64[0] == 0) && (nsi->daddr.ipv6.addr64[1] == 0))) // Zero addr
            return AF_UNSPEC;
    }
    else {
        return AF_UNSPEC;
    }

    //Read destination port
    bpf_probe_read(&nsi->dport, sizeof(u16), &is->inet_dport);
    bpf_probe_read(&nsi->sport, sizeof(u16), &is->inet_sport);

    // Socket for nowhere or system looking for port
    // This can be an attack vector that needs to be addressed in another opportunity
    if (nsi->sport == 0 || nsi->dport == 0)
        return AF_UNSPEC;


    return family;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0))
static __always_inline u8 select_protocol(struct sock *sk)
{
    u8 protocol = 0;

    int gso_max_segs_offset = offsetof(struct sock, sk_gso_max_segs);
    int sk_lingertime_offset = offsetof(struct sock, sk_lingertime);

    if (sk_lingertime_offset - gso_max_segs_offset == 4)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        bpf_probe_read(&protocol, sizeof(u8), (void *)((long)&sk->sk_gso_max_segs) - 3);
    else
        bpf_probe_read(&protocol, sizeof(u8), (void *)((long)&sk->sk_wmem_queued) - 3);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        bpf_probe_read(&protocol, sizeof(u8), (void *)((long)&sk->sk_gso_max_segs) - 1);
    else
        bpf_probe_read(&protocol, sizeof(u8), (void *)((long)&sk->sk_wmem_queued) - 1);
#endif

    return protocol;
}
#endif // Kernel version 5.6.0

/************************************************************************************
 *
 *                                 General Socket Section
 *
 ***********************************************************************************/

SEC("kretprobe/inet_csk_accept")
int netdata_inet_csk_accept(struct pt_regs* ctx)
{
    return 0;
}

/************************************************************************************
 *
 *                                 TCP Section
 *
 ***********************************************************************************/

SEC("kretprobe/tcp_sendmsg")
int netdata_tcp_sendmsg(struct pt_regs* ctx)
{
    return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int netdata_tcp_retransmit_skb(struct pt_regs* ctx)
{
    return 0;
}

SEC("kprobe/tcp_set_state")
int netdata_tcp_set_state(struct pt_regs* ctx)
{
    return 0;
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/tcp.c#L1528
SEC("kprobe/tcp_cleanup_rbuf")
int netdata_tcp_cleanup_rbuf(struct pt_regs* ctx)
{
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int netdata_tcp_v4_connect(struct pt_regs* ctx)
{
    return 0;
}

SEC("kretprobe/tcp_v6_connect")
int netdata_tcp_v6_connect(struct pt_regs* ctx)
{
    return 0;
}

/************************************************************************************
 *
 *                                 UDP Section
 *
 ***********************************************************************************/

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/udp.c#L1726
SEC("kprobe/udp_recvmsg")
int trace_udp_recvmsg(struct pt_regs* ctx)
{
    return 0;
}

SEC("kretprobe/udp_sendmsg")
int trace_udp_sendmsg(struct pt_regs* ctx)
{
    return 0;
}

char _license[] SEC("license") = "GPL";

