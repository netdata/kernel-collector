#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#include "netdata_core.h"
#include "netdata_socket.h"

// Copied from https://elixir.bootlin.com/linux/v5.15.5/source/include/linux/socket.h#L175
#define AF_UNSPEC	0
#define AF_INET		2
#define AF_INET6	10


/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

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

/***********************************************************************************
 *
 *                                SOCKET COMMON
 *
 ***********************************************************************************/

static __always_inline short unsigned int set_idx_value(netdata_socket_idx_t *nsi, struct inet_sock *is)
{
    // Read Family
    short unsigned int family;
    BPF_CORE_READ_INTO(&family, is, sk.__sk_common.skc_family);
    // Read source and destination IPs
    if ( family == AF_INET ) { //AF_INET
        BPF_CORE_READ_INTO(&nsi->saddr.addr32, is, sk.__sk_common.skc_rcv_saddr );
        BPF_CORE_READ_INTO(&nsi->daddr.addr32, is, sk.__sk_common.skc_daddr );

        if (!nsi->saddr.addr32[0] || !nsi->daddr.addr32[0])
            return AF_UNSPEC;
    } else if ( family == AF_INET6 ) {
#if defined(NETDATA_CONFIG_IPV6)
        BPF_CORE_READ_INTO(&nsi->saddr.addr8, is, sk.__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8 );
        BPF_CORE_READ_INTO(&nsi->daddr.addr8, is, sk.__sk_common.skc_v6_daddr.in6_u.u6_addr8 );

        if ( ((!nsi->saddr.addr64[0]) && (!nsi->saddr.addr64[1])) || ((!nsi->daddr.addr64[0]) && (!nsi->daddr.addr64[1])))
            return AF_UNSPEC;
#endif
    } else {
        return AF_UNSPEC;
    }

    //Read ports
    BPF_CORE_READ_INTO(&nsi->dport, is, sk.__sk_common.skc_dport);
    BPF_CORE_READ_INTO(&nsi->sport, is, sk.__sk_common.skc_num);

    return family;
}

static __always_inline void update_socket_stats(netdata_socket_t *ptr, __u64 sent, __u64 received, __u32 retransmitted)
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

    libnetdata_update_u32(&ptr->retransmit, retransmitted);
}

// Use __always_inline instead inline to keep compatiblity with old kernels
// https://docs.cilium.io/en/v1.8/bpf/
// The condition to test kernel was added, because __always_inline broke the epbf.plugin
// on CentOS 7 and Ubuntu 18.04 (kernel 4.18)
static __always_inline void update_socket_table(struct inet_sock *is,
                                                __u64 sent,
                                                __u64 received,
                                                __u32 retransmitted,
                                                __u16 protocol)
{
    __u16 family;
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
            bpf_map_delete_elem(tbl, &idx);
    } else {
        // This will be present while we do not have network viewer.
        if (protocol == IPPROTO_UDP && received)
            return;

        data.first = bpf_ktime_get_ns();
        data.protocol = protocol;
        update_socket_stats(&data, sent, received, retransmitted);

        bpf_map_update_elem(tbl, &idx, &data, BPF_ANY);
    }
}

static __always_inline void ebpf_socket_reset_bandwidth(__u32 pid, __u32 tgid)
{
    netdata_bandwidth_t data = { };
    data.pid = tgid;
    data.first = bpf_ktime_get_ns();

    bpf_map_update_elem(&tbl_bandwidth, &pid, &data, BPF_ANY);
}

static __always_inline void update_pid_cleanup()
{
    netdata_bandwidth_t *b;
    netdata_bandwidth_t data = { };

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    b = (netdata_bandwidth_t *) bpf_map_lookup_elem(&tbl_bandwidth, &pid);
    if (b) {
        if (b->pid != tgid)
            ebpf_socket_reset_bandwidth(pid, tgid);

        libnetdata_update_u64(&b->close, 1);
    } else {
        data.pid = tgid;
        data.first = bpf_ktime_get_ns();
        data.ct = data.first;
        data.close = 1;

        bpf_map_update_elem(&tbl_bandwidth, &pid, &data, BPF_ANY);
    }
}

static __always_inline void update_pid_bandwidth(__u64 sent, __u64 received, __u8 protocol)
{
    netdata_bandwidth_t *b;
    netdata_bandwidth_t data = { };

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    b = (netdata_bandwidth_t *) bpf_map_lookup_elem(&tbl_bandwidth, &pid);
    if (b) {
        if (b->pid != tgid)
            ebpf_socket_reset_bandwidth(pid, tgid);

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

static __always_inline void update_pid_table(__u64 sent, __u64 received, __u8 protocol)
{
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;

    __u32 *apps = bpf_map_lookup_elem(&socket_ctrl ,&key);
    if (apps)
        if (*apps == 1)
            update_pid_bandwidth((__u64)sent, received, protocol);
}

static __always_inline int common_tcp_send_message(struct inet_sock *is, size_t sent, int ret)
{
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_TCP_SENDMSG, 1);

    if (ret < 0) {
        libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_ERROR_TCP_SENDMSG, 1);
        return 0;
    }

    update_socket_table(is, sent, 0, 0, (__u16)IPPROTO_TCP);
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_BYTES_TCP_SENDMSG, sent);

    update_pid_table((__u64)sent, 0, IPPROTO_TCP);

    return 0;
}

static __always_inline int common_udp_send_message(struct inet_sock *is, size_t sent, int ret)
{
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_UDP_SENDMSG, 1);

    if (ret < 0) {
        libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_ERROR_UDP_SENDMSG, 1);
        return 0;
    }

    update_socket_table(is, sent, 0, 0, (__u16)IPPROTO_UDP);

    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_BYTES_UDP_SENDMSG, (__u64) sent);

    update_pid_table((__u64)sent, 0, IPPROTO_UDP);

    return 0;
}

static inline int netdata_common_inet_csk_accept(struct sock *sk)
{
    if (!sk)
        return 0;

    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_num);

    __u8 *value = (__u8 *)bpf_map_lookup_elem(&tbl_lports, &dport);
    if (!value) {
        __u8 value = 1;
        bpf_map_update_elem(&tbl_lports, &dport, &value, BPF_ANY);
    }

    return 0;
}

static inline int netdata_common_tcp_retransmit(struct inet_sock *is)
{
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_TCP_RETRANSMIT, 1);

    update_socket_table(is, 0, 0, 1, (__u16)IPPROTO_TCP);

    update_pid_table(0, 0, IPPROTO_TCP);

    return 0;
}

static inline int netdata_common_tcp_cleanup_rbuf(int copied, struct inet_sock *is, __u64 received)
{
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_TCP_CLEANUP_RBUF, 1);

    if (copied < 0) {
        libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_ERROR_TCP_CLEANUP_RBUF, 1);
        return 0;
    }

    update_socket_table(is, 0, (__u64)copied, 1, (__u16)IPPROTO_TCP);

    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_BYTES_TCP_CLEANUP_RBUF, received);

    update_pid_table(0, received, IPPROTO_TCP);

    return 0;
}

static inline int netdata_common_tcp_close(struct inet_sock *is)
{
    void *tbl;
    netdata_socket_t *val;
    __u16 family;
    netdata_socket_idx_t idx = { };
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;

    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_TCP_CLOSE, 1);

    __u32 *apps = bpf_map_lookup_elem(&socket_ctrl ,&key);
    if (apps)
        if (*apps == 1)
            update_pid_cleanup();

    family =  set_idx_value(&idx, is);
    if (!family)
        return 0;

    tbl = (family == AF_INET6)?(void *)&tbl_conn_ipv6:(void *)&tbl_conn_ipv4;
    val = (netdata_socket_t *) bpf_map_lookup_elem(tbl, &idx);
    if (val) {
        bpf_map_delete_elem(tbl, &idx);
    }

    return 0;
}

static inline int netdata_common_udp_recvmsg(struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_UDP_RECVMSG, 1);

    bpf_map_update_elem(&tbl_nv_udp, &pid_tgid, &sk, BPF_ANY);

    return 0;
}

/***********************************************************************************
 *
 *                             SOCKET SECTION(kprobe)
 *
 ***********************************************************************************/

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(netdata_inet_csk_accept_kretprobe)
{
    struct sock *sk = (struct sock*)PT_REGS_RC(ctx);

    return netdata_common_inet_csk_accept(sk);
}

SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(netdata_tcp_retransmit_skb_kprobe)
{
    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));

    return netdata_common_tcp_retransmit(is);
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/tcp.c#L1528
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(netdata_tcp_cleanup_rbuf_kprobe)
{
    int copied = (int)PT_REGS_PARM2(ctx);
    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));
    __u64 received = (__u64) copied;

    return netdata_common_tcp_cleanup_rbuf(copied, is, received);
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(netdata_tcp_close_kprobe)
{
    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));

    return netdata_common_tcp_close(is);
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/udp.c#L1726
SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(netdata_udp_recvmsg_kprobe)
{
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);

    return netdata_common_udp_recvmsg(sk);
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(netdata_udp_recvmsg_kretprobe)
{
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_UDP_RECVMSG, 1);

     struct sock **skpp = bpf_map_lookup_elem(&tbl_nv_udp, &pid_tgid);
    if (skpp == 0) {
        return 0;
    }

    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));

    bpf_map_delete_elem(&tbl_nv_udp, &pid_tgid);
    __u64 received = (__u64) PT_REGS_RC(ctx);
    update_socket_table(is, 0, received, 0, (__u16)IPPROTO_UDP);

    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_BYTES_UDP_RECVMSG, received);

    update_pid_table(0, received, IPPROTO_UDP);

    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(netdata_tcp_sendmsg_kretprobe)
{
    int ret = (int)PT_REGS_RC(ctx);
    size_t sent = (ret > 0 )?(size_t) ret : 0;

    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));
    return common_tcp_send_message(is, sent, ret);
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(netdata_tcp_sendmsg_kprobe)
{
    size_t sent = (size_t) PT_REGS_PARM3(ctx);
    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));

    return common_tcp_send_message(is, sent, 0);
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/udp.c#L965
SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(netdata_udp_sendmsg_kretprobe)
{
    int ret = (int)PT_REGS_RC(ctx);
    size_t sent = (ret > 0 )?(size_t)ret : 0;
    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));

    return common_udp_send_message(is, sent, ret);
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(netdata_udp_sendmsg_kprobe)
{
    size_t sent = (size_t)PT_REGS_PARM3(ctx);
    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));

    return common_udp_send_message(is, sent, 0);
}

/***********************************************************************************
 *
 *                             SOCKET SECTION(tracepoint)
 *
 ***********************************************************************************/

SEC("fentry/inet_csk_accept")
int BPF_PROG(netdata_inet_csk_accept_fentry, struct sock *sk)
{
    return netdata_common_inet_csk_accept(sk);
}

SEC("fentry/tcp_retransmit_skb")
int BPF_PROG(netdata_tcp_retransmit_skb_fentry, struct sock *sk)
{
    struct inet_sock *is = (struct inet_sock *)sk;

    return netdata_common_tcp_retransmit(is);
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/tcp.c#L1528
SEC("fentry/tcp_cleanup_rbuf")
int BPF_PROG(netdata_tcp_cleanup_rbuf_fentry, struct sock *sk, int copied)
{
    struct inet_sock *is = (struct inet_sock *)sk;
    __u64 received = (__u64) copied;

    return netdata_common_tcp_cleanup_rbuf(copied, is, received);
}

SEC("fentry/tcp_close")
int BPF_PROG(netdata_tcp_close_fentry, struct sock *sk)
{
    struct inet_sock *is = (struct inet_sock *)sk;

    return netdata_common_tcp_close(is);
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/udp.c#L1726
SEC("fentry/udp_recvmsg")
int BPF_PROG(netdata_udp_recvmsg_fentry, struct sock *sk)
{
    return netdata_common_udp_recvmsg(sk);
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(netdata_tcp_sendmsg_fentry, struct sock *sk, struct msghdr *msg, size_t size)
{
    struct inet_sock *is = (struct inet_sock *)sk;

    return common_tcp_send_message(is, size, 0);
}

SEC("fexit/tcp_sendmsg")
int BPF_PROG(netdata_tcp_sendmsg_fexit, struct sock *sk, struct msghdr *msg, size_t size, int ret)
{
    size_t sent = (ret > 0 )?(size_t) ret : 0;

    struct inet_sock *is = (struct inet_sock *)sk;
    return common_tcp_send_message(is, sent, ret);
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(netdata_udp_sendmsg_fentry, struct sock *sk, struct msghdr *msg, size_t len)
{
    struct inet_sock *is = (struct inet_sock *)sk;

    return common_udp_send_message(is, len, 0);
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/udp.c#L965
SEC("fexit/udp_sendmsg")
int BPF_PROG(netdata_udp_sendmsg_fexit, struct sock *sk, struct msghdr *msg, size_t len, int ret)
{
    size_t sent = (ret > 0 )?(size_t)ret : 0;
    struct inet_sock *is = (struct inet_sock *)sk;

    return common_udp_send_message(is, sent, ret);
}

char _license[] SEC("license") = "GPL";

