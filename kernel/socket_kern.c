#define KBUILD_MODNAME "socket_netdata"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_vlan.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,4,14))
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#else
#include "netdata_bpf_helpers.h"
#endif
#include "netdata_ebpf.h"

/************************************************************************************
 *
 *                              Hash Table Section
 *
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,4,14))
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, netdata_bandwidth_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} tbl_bandwidth SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_SOCKET_COUNTER);
} tbl_global_sock SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, netdata_socket_idx_t);
    __type(value, netdata_socket_t);
    __uint(max_entries, 65536);
} tbl_conn_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, netdata_socket_idx_t);
    __type(value, netdata_socket_t);
    __uint(max_entries, 65536);
} tbl_conn_ipv6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u64);
    __type(value, void *);
    __uint(max_entries, 8192);
} tbl_nv_udp SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, 65536);
} tbl_lports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} socket_ctrl SEC(".maps");

#else

struct bpf_map_def SEC("maps") tbl_bandwidth = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u32),
    .value_size = sizeof(netdata_bandwidth_t),
    .max_entries = 65536
};

struct bpf_map_def SEC("maps") tbl_global_sock = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries =  NETDATA_SOCKET_COUNTER
};

struct bpf_map_def SEC("maps") tbl_conn_ipv4 = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(netdata_socket_idx_t),
    .value_size = sizeof(netdata_socket_t),
    .max_entries = 65536
};

struct bpf_map_def SEC("maps") tbl_conn_ipv6 = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(netdata_socket_idx_t),
    .value_size = sizeof(netdata_socket_t),
    .max_entries = 65536
};

struct bpf_map_def SEC("maps") tbl_nv_udp = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u64),
    .value_size = sizeof(void *),
    .max_entries = 8192
};

struct bpf_map_def SEC("maps") tbl_lports = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u16),
    .value_size = sizeof(__u8),
    .max_entries =  65536
};

struct bpf_map_def SEC("maps") socket_ctrl = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = NETDATA_CONTROLLER_END
};

#endif

/************************************************************************************
 *
 *                                 Global Socket Section
 *
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,19,0))
static __always_inline __u16 set_idx_value(netdata_socket_idx_t *nsi, struct inet_sock *is)
#else
static inline __u16 set_idx_value(netdata_socket_idx_t *nsi, struct inet_sock *is)
#endif
{
    __u16 family;

    // Read Family
    bpf_probe_read(&family, sizeof(u16), &is->sk.__sk_common.skc_family);
    // Read source and destination IPs
    if ( family == AF_INET ) { //AF_INET
        bpf_probe_read(&nsi->saddr.addr32[0], sizeof(u32), &is->inet_rcv_saddr);
        bpf_probe_read(&nsi->daddr.addr32[0], sizeof(u32), &is->inet_daddr);

        if (!nsi->saddr.addr32[0] || !nsi->daddr.addr32[0])
            return AF_UNSPEC;
    }
    // Check necessary according https://elixir.bootlin.com/linux/v5.6.14/source/include/net/sock.h#L199
#if IS_ENABLED(CONFIG_IPV6)
    else if ( family == AF_INET6 ) {
        struct in6_addr *addr6 = &is->sk.sk_v6_rcv_saddr;
        bpf_probe_read(&nsi->saddr.addr8,  sizeof(__u8)*16, &addr6->s6_addr);

        addr6 = &is->sk.sk_v6_daddr;
        bpf_probe_read(&nsi->daddr.addr8,  sizeof(__u8)*16, &addr6->s6_addr);

        if ( ((!nsi->saddr.addr64[0]) && (!nsi->saddr.addr64[1])) || ((!nsi->daddr.addr64[0]) && (!nsi->daddr.addr64[1])))
            return AF_UNSPEC;
    }
#endif
    else {
        return AF_UNSPEC;
    }

    //Read destination port
    bpf_probe_read(&nsi->dport, sizeof(u16), &is->inet_dport);
    bpf_probe_read(&nsi->sport, sizeof(u16), &is->inet_num);
    nsi->sport = ntohs(nsi->sport);

    return family;
}

// Update time and bytes sent and received
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,19,0))
static __always_inline void update_socket_stats(netdata_socket_t *ptr, __u64 sent, __u64 received, __u16 retransmitted)
#else
static inline void update_socket_stats(netdata_socket_t *ptr, __u64 sent, __u64 received, __u16 retransmitted)
#endif
{
    ptr->ct = bpf_ktime_get_ns();

    if (sent) {
        libnetdata_update_u64(&ptr->sent_packets, 1);
        libnetdata_update_u64(&ptr->sent_bytes, sent);
    }

    if (received) {
        libnetdata_update_u64(&ptr->recv_packets, 1);
        libnetdata_update_u64(&ptr->recv_bytes, received);
    }

    // We can use update_u64, it was overwritten
    // the values
    ptr->retransmit += retransmitted;
}

// Use __always_inline instead inline to keep compatiblity with old kernels
// https://docs.cilium.io/en/v1.8/bpf/
// The condition to test kernel was added, because __always_inline broke the epbf.plugin
// on CentOS 7 and Ubuntu 18.04 (kernel 4.18)
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,19,0))
static __always_inline  void update_socket_table(struct pt_regs* ctx,
                                                __u64 sent,
                                                __u64 received,
                                                __u16 retransmitted,
                                                __u8 protocol)
#else
static inline void update_socket_table(struct pt_regs* ctx,
                                                __u64 sent,
                                                __u64 received,
                                                __u16 retransmitted,
                                                __u8 protocol)
#endif
{
    __u16 family;
    struct inet_sock *is = inet_sk((struct sock *)PT_REGS_PARM1(ctx));
    void *tbl;
    netdata_socket_idx_t idx = { };

    family = set_idx_value(&idx, is);
    if (!family)
        return;

    tbl = (family == AF_INET6)?(void *)&tbl_conn_ipv6:(void *)&tbl_conn_ipv4;

    netdata_socket_t *val;
    netdata_socket_t data = { };

    val = (netdata_socket_t *) bpf_map_lookup_elem(tbl, &idx);
    if (val) {
        update_socket_stats(val, sent, received, retransmitted);
        if (protocol == IPPROTO_UDP)
            val->removeme = 1;
    } else {
        data.first = bpf_ktime_get_ns();
        data.protocol = protocol;
        update_socket_stats(&data, sent, received, retransmitted);

        bpf_map_update_elem(tbl, &idx, &data, BPF_ANY);
    }
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,19,0))
static __always_inline void update_pid_stats(__u64 sent, __u64 received, __u8 protocol)
#else
static inline void update_pid_stats(__u64 sent, __u64 received, __u8 protocol)
#endif
{
    netdata_bandwidth_t *b;
    netdata_bandwidth_t data = { };

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    b = (netdata_bandwidth_t *) bpf_map_lookup_elem(&tbl_bandwidth, &pid);
    if (b) {
        b->ct = bpf_ktime_get_ns();

        if (sent)
            libnetdata_update_u64(&b->bytes_sent, sent);

        if (received)
            libnetdata_update_u64(&b->bytes_received, received);

        if (protocol == IPPROTO_TCP) {
            if (sent) {
                libnetdata_update_u64(&b->call_tcp_sent, 1);
            } else if (received) {
                libnetdata_update_u64(&b->call_tcp_received, 1);
            } else {
                libnetdata_update_u64(&b->retransmit, 1);
            }
        } else {
                libnetdata_update_u64((sent) ? &b->call_udp_sent : &b->call_udp_received, 1);
        } 
    } else {
        data.pid = tgid;
        data.first = bpf_ktime_get_ns();
        data.ct = data.first;
        data.bytes_sent = sent;
        data.bytes_received = received;
        if (protocol == IPPROTO_TCP) {
            if (sent) {
                data.call_tcp_sent = 1;
            } else if (received) {
                data.call_tcp_received = 1;
            } else {
                data.retransmit = 1;
            }
        } else {
            if (sent) {
                data.call_udp_sent = 1;
            } else {
                data.call_udp_received = 1;
            }
        }

        bpf_map_update_elem(&tbl_bandwidth, &pid, &data, BPF_ANY);
    }
}

/************************************************************************************
 *
 *                                 General Socket Section
 *
 ***********************************************************************************/

SEC("kretprobe/inet_csk_accept")
int netdata_inet_csk_accept(struct pt_regs* ctx)
{
    struct sock *sk = (struct sock*)PT_REGS_RC(ctx);
    if (!sk)
        return 0;

    __u16 dport;
    bpf_probe_read(&dport, sizeof(u16), &sk->__sk_common.skc_num);

    __u8 *value = (__u8 *)bpf_map_lookup_elem(&tbl_lports, &dport);
    if (!value) {
        __u8 value = 1;
        bpf_map_update_elem(&tbl_lports, &dport, &value, BPF_ANY);
    }

    return 0;
}

/************************************************************************************
 *
 *                                 TCP Section
 *
 ***********************************************************************************/

#if NETDATASEL < 2
SEC("kretprobe/tcp_sendmsg")
#else
SEC("kprobe/tcp_sendmsg")
#endif
int netdata_tcp_sendmsg(struct pt_regs* ctx)
{
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    size_t sent;
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0) {
        libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_ERROR_TCP_SENDMSG, 1);
        return 0;
    }

    sent = (size_t) ret;
#else 
    sent = (size_t)PT_REGS_PARM3(ctx);
#endif

    update_socket_table(ctx, sent, 0, 0, IPPROTO_TCP);
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_BYTES_TCP_SENDMSG, sent);

    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_TCP_SENDMSG, 1);

    __u32 *apps = bpf_map_lookup_elem(&socket_ctrl ,&key);
    if (apps)
        if (*apps == 1)
            update_pid_stats((__u64)sent, 0, IPPROTO_TCP);

    return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int netdata_tcp_retransmit_skb(struct pt_regs* ctx)
{
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_TCP_RETRANSMIT, 1);

    update_socket_table(ctx, 0, 0, 1, IPPROTO_TCP);

    __u32 *apps = bpf_map_lookup_elem(&socket_ctrl ,&key);
    if (apps)
        if (*apps == 1)
            update_pid_stats(0, 0, IPPROTO_TCP);

    return 0;
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/tcp.c#L1528
SEC("kprobe/tcp_cleanup_rbuf")
int netdata_tcp_cleanup_rbuf(struct pt_regs* ctx)
{
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    int copied = (int)PT_REGS_PARM2(ctx);

    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_TCP_CLEANUP_RBUF, 1);

    if (copied < 0) {
        libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_ERROR_TCP_CLEANUP_RBUF, 1);
        return 0;
    }

    __u64 received = (__u64) PT_REGS_PARM2(ctx);

    update_socket_table(ctx, 0, (__u64)copied, 1, IPPROTO_TCP);
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_BYTES_TCP_CLEANUP_RBUF, received);

    __u32 *apps = bpf_map_lookup_elem(&socket_ctrl ,&key);
    if (apps)
        if (*apps == 1)
            update_pid_stats(0, received, IPPROTO_TCP);

    return 0;
}

SEC("kprobe/tcp_close")
int netdata_tcp_close(struct pt_regs* ctx)
{
    void *tbl;
    netdata_socket_t *val;
    __u16 family;
    netdata_socket_idx_t idx = { };

    struct inet_sock *is = inet_sk((struct sock *)PT_REGS_PARM1(ctx));

    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_TCP_CLOSE, 1);

    family =  set_idx_value(&idx, is);
    if (!family)
        return 0;

    tbl = (family == AF_INET6)?(void *)&tbl_conn_ipv6:(void *)&tbl_conn_ipv4;
    val = (netdata_socket_t *) bpf_map_lookup_elem(tbl, &idx);
    if (val) {
        //The socket information needs to be removed after read on user ring
        val->removeme = 1;
    }

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
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);

    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_UDP_RECVMSG, 1);

    bpf_map_update_elem(&tbl_nv_udp, &pid_tgid, &sk, BPF_ANY);

    return 0;
}

SEC("kretprobe/udp_recvmsg")
int trace_udp_ret_recvmsg(struct pt_regs* ctx)
{
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_UDP_RECVMSG, 1);

     struct sock **skpp = bpf_map_lookup_elem(&tbl_nv_udp, &pid_tgid);
    if (skpp == 0) {
        return 0;
    }

    bpf_map_delete_elem(&tbl_nv_udp, &pid_tgid);
    update_socket_table(ctx, 0, 0, 1, IPPROTO_TCP);

    __u64 received = (__u64) PT_REGS_RC(ctx);
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_BYTES_UDP_RECVMSG, received);

    __u32 *apps = bpf_map_lookup_elem(&socket_ctrl ,&key);
    if (apps)
        if (*apps == 1)
            update_pid_stats(0, received, IPPROTO_UDP);

    return 0;
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/udp.c#L965
#if NETDATASEL < 2
SEC("kretprobe/udp_sendmsg")
#else
SEC("kprobe/udp_sendmsg")
#endif
int trace_udp_sendmsg(struct pt_regs* ctx)
{
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_UDP_SENDMSG, 1);

    size_t sent;
#if NETDATASEL < 2
    sent = (ret > 0 )?(size_t)ret:0;
#else
    sent = (size_t)PT_REGS_PARM3(ctx);
#endif

    update_socket_table(ctx, 0, 0, 1, IPPROTO_UDP);

    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_BYTES_UDP_SENDMSG, (__u64) sent);

#if NETDATASEL < 2
    if (ret < 0) {
        libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_ERROR_UDP_SENDMSG, 1);
    }
#endif

    __u32 *apps = bpf_map_lookup_elem(&socket_ctrl ,&key);
    if (apps)
        if (*apps == 1)
            update_pid_stats((__u64) sent, 0, IPPROTO_UDP);

    return 0;
}

char _license[] SEC("license") = "GPL";

