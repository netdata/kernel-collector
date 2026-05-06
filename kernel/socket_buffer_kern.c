#define KBUILD_MODNAME "socket_buffer_netdata"
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
#include "netdata_arena_common.h"
#include "netdata_socket_buffer.h"

/************************************************************************************
 *
 *                              Hash Table Section
 *
 ***********************************************************************************/

NETDATA_BPF_RINGBUF_DEF(socket_events, NETDATA_SOCKET_RINGBUF_SIZE);
NETDATA_BPF_PERCPU_ARRAY_DEF(tbl_global_sock, __u32, __u64, NETDATA_SOCKET_COUNTER);
NETDATA_BPF_PERCPU_HASH_DEF(tbl_nv_udp, __u64, void *, 4096);
NETDATA_BPF_HASH_DEF(tbl_lports, netdata_passive_connection_idx_t, netdata_passive_connection_t, 1024);
NETDATA_BPF_ARRAY_DEF(socket_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

/************************************************************************************
 *
 *                                 Common Section
 *
 ***********************************************************************************/

static __always_inline __u16 set_idx_value(netdata_socket_idx_t *nsi, struct inet_sock *is)
{
    __u16 family;

    bpf_probe_read(&family, sizeof(u16), &is->sk.__sk_common.skc_family);
    if (family == AF_INET) {
        bpf_probe_read(&nsi->saddr.addr32[0], sizeof(u32), &is->inet_saddr);
        bpf_probe_read(&nsi->daddr.addr32[0], sizeof(u32), &is->inet_daddr);

        if ((nsi->saddr.addr32[0] == 16777343 || nsi->daddr.addr32[0] == 16777343) ||
            (nsi->saddr.addr32[0] == 0 || nsi->daddr.addr32[0] == 0))
            return AF_UNSPEC;
    }
#if IS_ENABLED(CONFIG_IPV6)
    else if (family == AF_INET6) {
        __u8 (*addr6)[16] = &is->sk.__sk_common.skc_v6_rcv_saddr.s6_addr;
        bpf_probe_read(&nsi->saddr.addr8, sizeof(__u8) * 16, addr6);

        addr6 = &is->sk.__sk_common.skc_v6_daddr.s6_addr;
        bpf_probe_read(&nsi->daddr.addr8, sizeof(__u8) * 16, addr6);

        if (((nsi->saddr.addr64[0] == 0) && (nsi->saddr.addr64[1] == 72057594037927936)) ||
            ((nsi->daddr.addr64[0] == 0) && (nsi->daddr.addr64[1] == 72057594037927936)))
            return AF_UNSPEC;

        if (((nsi->saddr.addr64[0] == 0) && (nsi->saddr.addr64[1] == 0)) ||
            ((nsi->daddr.addr64[0] == 0) && (nsi->daddr.addr64[1] == 0)))
            return AF_UNSPEC;
    }
#endif
    else {
        return AF_UNSPEC;
    }

    bpf_probe_read(&nsi->dport, sizeof(u16), &is->inet_dport);
    if (nsi->dport == 0)
        return AF_UNSPEC;

    __u32 tgid = 0;
    nsi->pid = netdata_get_pid(&socket_ctrl, &tgid);

    return family;
}

static __always_inline void update_socket_stats(netdata_socket_t __arena *ptr,
                                                __u64 sent,
                                                __u64 received,
                                                __u32 retransmitted,
                                                __u16 protocol)
{
    ptr->ct = bpf_ktime_get_ns();

    if (sent) {
        if (protocol == IPPROTO_TCP) {
            ptr->tcp.call_tcp_sent += 1;
            ptr->tcp.tcp_bytes_sent += sent;
            ptr->tcp.retransmit += retransmitted;
        } else {
            ptr->udp.call_udp_sent += 1;
            ptr->udp.udp_bytes_sent += sent;
        }
    }

    if (received) {
        if (protocol == IPPROTO_TCP) {
            ptr->tcp.call_tcp_received += 1;
            ptr->tcp.tcp_bytes_received += received;
        } else {
            ptr->udp.call_udp_received += 1;
            ptr->udp.udp_bytes_received += received;
        }
    }
}

static __always_inline void update_socket_common(netdata_socket_t __arena *data, __u16 protocol, __u16 family)
{
    char comm[TASK_COMM_LEN];

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
    bpf_get_current_comm(comm, TASK_COMM_LEN);
    #pragma unroll
    for (int i = 0; i < TASK_COMM_LEN; i++)
        data->name[i] = comm[i];
#else
    data->name[0] = '\0';
#endif

    data->first = bpf_ktime_get_ns();
    data->protocol = protocol;
    data->family = family;
}

static __always_inline struct netdata_socket_event_t __arena *
socket_event_reserve(struct pt_regs *ctx, __u16 *family, netdata_socket_idx_t *idx, __u16 protocol)
{
    struct inet_sock *is = inet_sk((struct sock *)PT_REGS_PARM1(ctx));
    struct netdata_socket_event_t __arena *ev;

    if (!is)
        return NULL;

    *family = set_idx_value(idx, is);
    if (*family == AF_UNSPEC)
        return NULL;

    ev = bpf_ringbuf_reserve(&socket_events, sizeof(*ev), 0);
    if (!ev)
        return NULL;

    __builtin_memset(ev, 0, sizeof(*ev));
    ev->idx = *idx;
    update_socket_common(&ev->data, protocol, *family);

    return ev;
}

static __always_inline void emit_socket_event(struct pt_regs *ctx,
                                              __u64 sent,
                                              __u64 received,
                                              __u32 retransmitted,
                                              __u16 protocol,
                                              __u32 state)
{
    netdata_socket_idx_t idx = { };
    __u16 family;
    struct netdata_socket_event_t __arena *ev = socket_event_reserve(ctx, &family, &idx, protocol);

    if (!ev)
        return;

    ev->data.tcp.state = state;
    update_socket_stats(&ev->data, sent, received, retransmitted, protocol);
    bpf_ringbuf_submit(ev, 0);
}

static __always_inline void emit_socket_close_event(struct pt_regs *ctx)
{
    netdata_socket_idx_t idx = { };
    __u16 family;
    struct netdata_socket_event_t __arena *ev = socket_event_reserve(ctx, &family, &idx, IPPROTO_TCP);

    if (!ev)
        return;

    ev->data.tcp.close = 1;
    bpf_ringbuf_submit(ev, 0);
}

static __always_inline void emit_socket_connect_event(struct pt_regs *ctx)
{
    netdata_socket_idx_t idx = { };
    __u16 family;
    struct netdata_socket_event_t __arena *ev = socket_event_reserve(ctx, &family, &idx, IPPROTO_TCP);

    if (!ev)
        return;

    if (family == AF_INET)
        ev->data.tcp.ipv4_connect = 1;
    else
        ev->data.tcp.ipv6_connect = 1;

    bpf_ringbuf_submit(ev, 0);
}

static __always_inline void emit_socket_external_origin_event(struct sock *sk, __u16 protocol)
{
    __u16 family;
    netdata_socket_idx_t nv_idx = { };
    struct netdata_socket_event_t __arena *ev;
    struct inet_sock *is = inet_sk(sk);

    if (!is)
        return;

    family = set_idx_value(&nv_idx, is);
    if (family == AF_UNSPEC)
        return;

    ev = bpf_ringbuf_reserve(&socket_events, sizeof(*ev), 0);
    if (!ev)
        return;

    __builtin_memset(ev, 0, sizeof(*ev));
    ev->idx = nv_idx;
    update_socket_common(&ev->data, protocol, family);
    ev->data.external_origin = 1;
    bpf_ringbuf_submit(ev, 0);
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
int netdata_inet_csk_accept(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!sk)
        return 0;

    u16 protocol;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0))
    bpf_probe_read(&protocol, sizeof(u16), &sk->sk_protocol);
#else
    protocol = (u16) select_protocol(sk);
#endif

    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
        return 0;

    netdata_passive_connection_idx_t idx = { };
    idx.protocol = protocol;
    bpf_probe_read(&idx.port, sizeof(u16), &sk->__sk_common.skc_num);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    netdata_passive_connection_t *value = (netdata_passive_connection_t *)bpf_map_lookup_elem(&tbl_lports, &idx);
    if (value) {
        value->tgid = tgid;
        value->pid = pid;
        libnetdata_update_u64(&value->counter, 1);
    } else {
        netdata_passive_connection_t data = { };
        data.tgid = tgid;
        data.pid = pid;
        data.counter = 1;
        bpf_map_update_elem(&tbl_lports, &idx, &data, BPF_ANY);
    }

    emit_socket_external_origin_event(sk, protocol);
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
int netdata_tcp_sendmsg(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_TCP_SENDMSG, 1);

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

    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_BYTES_TCP_SENDMSG, sent);
    emit_socket_event(ctx, sent, 0, 0, IPPROTO_TCP, 0);

    return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int netdata_tcp_retransmit_skb(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_TCP_RETRANSMIT, 1);
    emit_socket_event(ctx, 0, 0, 1, IPPROTO_TCP, 0);

    return 0;
}

SEC("kprobe/tcp_set_state")
int netdata_tcp_set_state(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_TCP_SET_STATE, 1);
    int state = PT_REGS_PARM2(ctx);

    emit_socket_event(ctx, 0, 0, 1, IPPROTO_TCP, state);
    return 0;
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/tcp.c#L1528
SEC("kprobe/tcp_cleanup_rbuf")
int netdata_tcp_cleanup_rbuf(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_TCP_CLEANUP_RBUF, 1);

    int copied = (int)PT_REGS_PARM2(ctx);
    if (copied < 0) {
        libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_ERROR_TCP_CLEANUP_RBUF, 1);
        return 0;
    }

    __u64 received = (__u64)PT_REGS_PARM2(ctx);
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_BYTES_TCP_CLEANUP_RBUF, received);
    emit_socket_event(ctx, 0, (__u64)copied, 1, IPPROTO_TCP, 0);

    return 0;
}

SEC("kprobe/tcp_close")
int netdata_tcp_close(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_TCP_CLOSE, 1);
    struct inet_sock *is = inet_sk((struct sock *)PT_REGS_PARM1(ctx));
    if (!is)
        return 0;

    emit_socket_close_event(ctx);
    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/tcp_v4_connect")
#else
SEC("kprobe/tcp_v4_connect")
#endif
int netdata_tcp_v4_connect(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_TCP_CONNECT_IPV4, 1);

#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0) {
        libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_ERROR_TCP_CONNECT_IPV4, 1);
        return 0;
    }
#endif

    emit_socket_connect_event(ctx);
    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/tcp_v6_connect")
#else
SEC("kprobe/tcp_v6_connect")
#endif
int netdata_tcp_v6_connect(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_TCP_CONNECT_IPV6, 1);
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0) {
        libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_ERROR_TCP_CONNECT_IPV6, 1);
        return 0;
    }
#endif

    emit_socket_connect_event(ctx);
    return 0;
}

/************************************************************************************
 *
 *                                 UDP Section
 *
 ***********************************************************************************/

SEC("kprobe/udp_recvmsg")
int trace_udp_recvmsg(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_UDP_RECVMSG, 1);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    bpf_map_update_elem(&tbl_nv_udp, &pid_tgid, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/udp_recvmsg")
int trace_udp_ret_recvmsg(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = bpf_map_lookup_elem(&tbl_nv_udp, &pid_tgid);
    if (skpp == 0)
        return 0;

    bpf_map_delete_elem(&tbl_nv_udp, &pid_tgid);
    __u64 received = (__u64)PT_REGS_RC(ctx);

    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_BYTES_UDP_RECVMSG, received);
    emit_socket_event(ctx, 0, received, 0, IPPROTO_UDP, 0);

    return 0;
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/udp.c#L965
#if NETDATASEL < 2
SEC("kretprobe/udp_sendmsg")
#else
SEC("kprobe/udp_sendmsg")
#endif
int trace_udp_sendmsg(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_UDP_SENDMSG, 1);

    size_t sent;
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0) {
        libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_ERROR_UDP_SENDMSG, 1);
        sent = 0;
    } else
        sent = (size_t)ret;
#else
    sent = (size_t)PT_REGS_PARM3(ctx);
#endif

    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_BYTES_UDP_SENDMSG, (__u64)sent);
    emit_socket_event(ctx, sent, 0, 0, IPPROTO_UDP, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";
