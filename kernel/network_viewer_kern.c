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
struct bpf_map_def SEC("maps") tbl_nv_socket = {
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

static __always_inline __u16 set_nv_idx_value(netdata_nv_idx_t *nvi, struct sock *sk)
{
    struct inet_sock *is = inet_sk(sk);
    __u16 family;

    // Read Family
    bpf_probe_read(&family, sizeof(u16), &is->sk.__sk_common.skc_family);
    // Read source and destination IPs
    if ( family == AF_INET ) { //AF_INET
        // bpf_probe_read(&nvi->saddr.addr32[0], sizeof(u32), &is->inet_rcv_saddr); // bind to local address
        bpf_probe_read(&nvi->saddr.ipv4, sizeof(u32), &is->inet_saddr);
        bpf_probe_read(&nvi->daddr.ipv4, sizeof(u32), &is->inet_daddr);
        if (nvi->saddr.ipv4 == 0 || nvi->daddr.ipv4 == 0) // Zero
            return AF_INET;
    }
    // Check necessary according https://elixir.bootlin.com/linux/v5.6.14/source/include/net/sock.h#L199
    else if ( family == AF_INET6 ) {
        // struct in6_addr *addr6 = &is->sk.sk_v6_rcv_saddr; // bind to local address
        struct in6_addr *addr6 = (struct in6_addr *)&is->sk.__sk_common.skc_v6_rcv_saddr.s6_addr;
        bpf_probe_read(&nvi->saddr.ipv6.in6_u.u6_addr8,  sizeof(__u8)*16, &addr6->s6_addr);

        addr6 = (struct in6_addr *)&is->sk.__sk_common.skc_v6_daddr.s6_addr;
        bpf_probe_read(&nvi->daddr.ipv6.in6_u.u6_addr8,  sizeof(__u8)*16, &addr6->s6_addr);
    }
    else {
        return AF_UNSPEC;
    }

    //Read destination port
    bpf_probe_read(&nvi->dport, sizeof(u16), &is->inet_dport);
    bpf_probe_read(&nvi->sport, sizeof(u16), &is->inet_sport);

    // Socket for nowhere or system looking for port
    // This can be an attack vector that needs to be addressed in another opportunity
    if (nvi->sport == 0 || nvi->dport == 0)
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

static __always_inline __s32 am_i_monitoring_protocol(struct sock *sk)
{
    u16 protocol;
    if (!sk)
        return 0;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0))
    protocol = 0;
    bpf_probe_read(&protocol, sizeof(u16), &sk->sk_protocol);
#else
    protocol = (u16) select_protocol(sk);
#endif

    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
        return 0;

    return 1;
} 

static __always_inline void set_common_tcp_nv_data(netdata_nv_data_t *data,
                                               struct sock *sk,
                                               __u16 family,
                                               int state,
                                               NETDATA_SOCKET_DIRECTION direction)
{
    const struct inet_connection_sock *icsk = inet_csk(sk);
    const struct tcp_sock *tp = tcp_sk(sk);
    __u8 icsk_pending;
    int rx_queue;
    struct timer_list tl;

    bpf_probe_read(&icsk_pending, sizeof(u8), &icsk->icsk_pending);
    bpf_probe_read(&tl, sizeof(struct timer_list), &sk->sk_timer);

    if (icsk_pending == ICSK_TIME_RETRANS ||
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
        icsk_pending == ICSK_TIME_REO_TIMEOUT ||
#else
        icsk_pending == ICSK_TIME_EARLY_RETRANS ||
#endif
        icsk_pending == ICSK_TIME_LOSS_PROBE) {
        data->wqueue = 1;
    } else if (icsk_pending == ICSK_TIME_PROBE0) {
        data->wqueue = 4;
    } else if (timer_pending(&tl)) {
        data->wqueue = 2;
    } else {
        data->wqueue = 0;
    }
    
    if (state == TCP_LISTEN)
        bpf_probe_read(&rx_queue, sizeof(rx_queue), &sk->sk_ack_backlog);
    else {
        u32 rcv_nxt, copied_seq;
        bpf_probe_read(&rcv_nxt, sizeof(u32), &tp->rcv_nxt);
        bpf_probe_read(&copied_seq, sizeof(u32), &tp->copied_seq);
        rx_queue = max_t(int, rcv_nxt - copied_seq, 0);
    }

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
    bpf_get_current_comm(&data->name, TASK_COMM_LEN);
#else
    data->name[0] = '\0';
#endif

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    // Only update this data when it is a new value
    if (!data->ts)
        data->ts = bpf_ktime_get_ns();
    data->timer = 0;
    bpf_probe_read(&data->retransmits, sizeof(data->retransmits), &icsk->icsk_retransmits);
    data->expires = 0;
    data->rqueue = rx_queue;

    if (data->direction == NETDATA_SOCKET_DIRECTION_NONE)
        data->direction = direction;

    data->family = family;
    data->protocol = IPPROTO_TCP;
}

static __always_inline void set_common_udp_nv_data(netdata_nv_data_t *data,
                                                   struct sock *sk,
                                                   __u16 family,
                                                   NETDATA_SOCKET_DIRECTION direction) {
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    // Only update this data when it is a new value
    if (!data->ts)
        data->ts = bpf_ktime_get_ns();

    data->protocol = IPPROTO_UDP;
    data->family = family;
    unsigned char state;
    bpf_probe_read(&state, sizeof(state), &sk->sk_state);
    data->state = (int)state;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
    bpf_get_current_comm(&data->name, TASK_COMM_LEN);
#else
    data->name[0] = '\0';
#endif

    if (data->direction == NETDATA_SOCKET_DIRECTION_NONE)
        data->direction = direction;
}

/************************************************************************************
 *
 *                                 External Connection
 *
 ***********************************************************************************/

SEC("kretprobe/inet_csk_accept")
int netdata_inet_csk_accept(struct pt_regs* ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!am_i_monitoring_protocol(sk))
        return 0;

    netdata_nv_idx_t idx = {};
    __u16 family = set_nv_idx_value(&idx, sk);
    NETDATA_SOCKET_DIRECTION direction = (idx.sport == idx.dport) ? NETDATA_SOCKET_DIRECTION_LISTEN : NETDATA_SOCKET_DIRECTION_INBOUND;
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, 0, direction);
        return 0;
    }

    if (!monitor_apps(&nv_ctrl))
        return 0;

    netdata_nv_data_t data = { };
    set_common_tcp_nv_data(&data, sk, family, 0, direction);

    bpf_map_update_elem(&tbl_nv_socket, &idx, &data, BPF_ANY);

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
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk || sk == (void *)1)
        return 0;

    netdata_nv_idx_t idx = {};
    __u16 family = set_nv_idx_value(&idx, sk);
    NETDATA_SOCKET_DIRECTION direction = (idx.sport == idx.dport) ? NETDATA_SOCKET_DIRECTION_LISTEN : NETDATA_SOCKET_DIRECTION_OUTBOUND | NETDATA_SOCKET_DIRECTION_INBOUND;
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, 0, direction);
        return 0;
    }

    if (!monitor_apps(&nv_ctrl))
        return 0;

    netdata_nv_data_t data = { };
    set_common_tcp_nv_data(&data, sk, family, 0, direction);

    bpf_map_update_elem(&tbl_nv_socket, &idx, &data, BPF_ANY);

    return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int netdata_tcp_retransmit_skb(struct pt_regs* ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk || sk == (void *)1)
        return 0;

    netdata_nv_idx_t idx = {};
    __u16 family = set_nv_idx_value(&idx, sk);
    NETDATA_SOCKET_DIRECTION direction = (idx.sport == idx.dport) ? NETDATA_SOCKET_DIRECTION_LISTEN : NETDATA_SOCKET_DIRECTION_OUTBOUND | NETDATA_SOCKET_DIRECTION_INBOUND;
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, 0, direction);
        return 0;
    }

    if (!monitor_apps(&nv_ctrl))
        return 0;

    netdata_nv_data_t data = { };
    set_common_tcp_nv_data(&data, sk, family, 0, direction);

    bpf_map_update_elem(&tbl_nv_socket, &idx, &data, BPF_ANY);

    return 0;
}

SEC("kprobe/tcp_set_state")
int netdata_tcp_set_state(struct pt_regs* ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk || sk == (void *)1)
        return 0;

    int state = (int)PT_REGS_PARM2(ctx);
    netdata_nv_idx_t idx = {};
    __u16 family = set_nv_idx_value(&idx, sk);
    NETDATA_SOCKET_DIRECTION direction = (idx.sport == idx.dport) ? NETDATA_SOCKET_DIRECTION_LISTEN : NETDATA_SOCKET_DIRECTION_OUTBOUND | NETDATA_SOCKET_DIRECTION_INBOUND;
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, state, direction);
        val->state = state;
        return 0;
    }

    if (!monitor_apps(&nv_ctrl))
        return 0;

    netdata_nv_data_t data = { };
    set_common_tcp_nv_data(&data, sk, family, state, direction);
    data.state = state;

    bpf_map_update_elem(&tbl_nv_socket, &idx, &data, BPF_ANY);

    return 0;
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/tcp.c#L1528
SEC("kprobe/tcp_cleanup_rbuf")
int netdata_tcp_cleanup_rbuf(struct pt_regs* ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk || sk == (void *)1)
        return 0;

    netdata_nv_idx_t idx = {};
    __u16 family = set_nv_idx_value(&idx, sk);
    NETDATA_SOCKET_DIRECTION direction = (idx.sport == idx.dport) ? NETDATA_SOCKET_DIRECTION_LISTEN : NETDATA_SOCKET_DIRECTION_OUTBOUND | NETDATA_SOCKET_DIRECTION_INBOUND;
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, 0, direction);
        return 0;
    }

    if (!monitor_apps(&nv_ctrl))
        return 0;

    netdata_nv_data_t data = { };
    set_common_tcp_nv_data(&data, sk, family, 0, direction);

    bpf_map_update_elem(&tbl_nv_socket, &idx, &data, BPF_ANY);

    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int netdata_tcp_v4_connect(struct pt_regs* ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk || sk == (void *)1)
        return 0;

    netdata_nv_idx_t idx = {};
    __u16 family = set_nv_idx_value(&idx, sk);
    NETDATA_SOCKET_DIRECTION direction = NETDATA_SOCKET_DIRECTION_OUTBOUND;
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, 0, direction);
        return 0;
    }

    if (!monitor_apps(&nv_ctrl))
        return 0;

    netdata_nv_data_t data = { };
    set_common_tcp_nv_data(&data, sk, family, 0, direction);

    bpf_map_update_elem(&tbl_nv_socket, &idx, &data, BPF_ANY);

    return 0;
}

SEC("kretprobe/tcp_v6_connect")
int netdata_tcp_v6_connect(struct pt_regs* ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk || sk == (void *)1)
        return 0;

    netdata_nv_idx_t idx = {};
    __u16 family = set_nv_idx_value(&idx, sk);
    NETDATA_SOCKET_DIRECTION direction = NETDATA_SOCKET_DIRECTION_OUTBOUND;
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, 0, direction);
        return 0;
    }

    if (!monitor_apps(&nv_ctrl))
        return 0;

    netdata_nv_data_t data = { };
    set_common_tcp_nv_data(&data, sk, family, 0, direction);

    bpf_map_update_elem(&tbl_nv_socket, &idx, &data, BPF_ANY);

    return 0;
}

SEC("kprobe/tcp_close")
int netdata_tcp_close(struct pt_regs* ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk || sk == (void *)1)
        return 0;

    netdata_nv_idx_t idx = {};
    __u16 family = set_nv_idx_value(&idx, sk);
    NETDATA_SOCKET_DIRECTION direction = NETDATA_SOCKET_DIRECTION_OUTBOUND;
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (!val)
        return 0;

    val->closed = 1;

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
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    netdata_nv_idx_t idx = {};
    __u16 family = set_nv_idx_value(&idx, sk);
    NETDATA_SOCKET_DIRECTION direction;
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        direction = NETDATA_SOCKET_DIRECTION_OUTBOUND;
        set_common_udp_nv_data(val, sk, family, direction);
        if (direction !=  NETDATA_SOCKET_DIRECTION_LISTEN)
            val->closed = 1;

        return 0;
    }

    if (!monitor_apps(&nv_ctrl))
        return 0;

    netdata_nv_data_t data = { };
    direction = NETDATA_SOCKET_DIRECTION_OUTBOUND | NETDATA_SOCKET_DIRECTION_INBOUND;
    set_common_udp_nv_data(&data, sk, family, direction);


    bpf_map_update_elem(&tbl_nv_socket, &idx, &data, BPF_ANY);

    return 0;
}

SEC("kretprobe/udp_sendmsg")
int trace_udp_sendmsg(struct pt_regs* ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    netdata_nv_idx_t idx = {};
    __u16 family = set_nv_idx_value(&idx, sk);
    NETDATA_SOCKET_DIRECTION direction = NETDATA_SOCKET_DIRECTION_OUTBOUND;
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_udp_nv_data(val, sk, family, direction);
        return 0;
    }

    if (!monitor_apps(&nv_ctrl))
        return 0;

    netdata_nv_data_t data = { };
    set_common_udp_nv_data(&data, sk, family, direction);

    bpf_map_update_elem(&tbl_nv_socket, &idx, &data, BPF_ANY);

    return 0;
}

char _license[] SEC("license") = "GPL";

