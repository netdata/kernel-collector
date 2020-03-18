#define KBUILD_MODNAME "network_viewer_stats"
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

#include <linux/ptrace.h>

#include "bpf_helpers.h"
# define NETDATA_SOCKET_COUNTER 10
# define NETDATA_GET_TGID 0X00000000FFFFFFFF

union netdata_ip {
    __u8 addr8[16];
    __u16 addr16[8];
    __u32 addr32[4];
};

struct netdata_statistic_t {
    __u32 tgid;

    __u64 first;
    __u64 ct;
    union netdata_ip saddr;
    union netdata_ip daddr;
    __u16 dport;
    __u16 retransmit;
    __u64 sent;
    __u64 recv;
    __u8 protocol;
    __u16 family;
    __u8 removeme;
};

struct netdata_port_statistic_t {
    __u64 count_sent_ipv4;
    __u64 count_sent_ipv6;
    __u64 data_sent_ipv4;
    __u64 data_sent_ipv6;

    __u64 count_received_ipv4;
    __u64 count_received_ipv6;
    __u64 data_received_ipv4;
    __u64 data_received_ipv6;
};

struct netdata_pid_stat_t {
    __u32 pid; //process id

    //Counter
    __u64 send_call; //output 
    __u64 recv_call;
    __u64 close_call;

    //Accumulator
    __u64 send_bytes;
    __u64 recv_bytes;

    //Counter
    __u32 send_err;
    __u32 recv_err;
    __u32 close_err;
};

struct bpf_map_def SEC("maps") tbl_nv_conn_stats = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct netdata_statistic_t),
    .max_entries = 65536
};

struct bpf_map_def SEC("maps") tbl_nv_udp_conn_stats = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(void *),
    .max_entries = 8192
};

struct bpf_map_def SEC("maps") tbl_nv_total_stats = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)) 
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = NETDATA_SOCKET_COUNTER
};

struct bpf_map_def SEC("maps") tbl_nv_tcp_stats = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u16),
    .value_size = sizeof(struct netdata_port_statistic_t),
    .max_entries = 65536
};

struct bpf_map_def SEC("maps") tbl_nv_udp_stats = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u16),
    .value_size = sizeof(struct netdata_port_statistic_t),
    .max_entries = 65536
};

/************************************************************************************
 *     
 *                                 COMMON Section
 *     
 ***********************************************************************************/

static void netdata_update_u32(u32 *res, u32 value)
{
    if ( (0xFFFFFFFF - *res) <= value)
        *res = value;
    else
        *res += value;
}

static void netdata_update_u64(u64 *res, u64 value) 
{
    if ( (0xFFFFFFFFFFFFFFFF - *res) <= value)
        *res = value;
    else 
        *res += value;
}

static void set_port_stats(struct bpf_map_def *ptr, __u16 port, __u64 sent, __u64 received, __u8 protocol)
{
    struct netdata_port_statistic_t *pport;
    struct netdata_port_statistic_t data = { };
    pport = (struct netdata_port_statistic_t *) bpf_map_lookup_elem(ptr, &port);
    if(pport){
        if (sent) {
            netdata_update_u64((protocol == AF_INET)?&pport->count_sent_ipv4:&pport->count_sent_ipv6, 1);
            netdata_update_u64((protocol == AF_INET)?&pport->data_sent_ipv4:&pport->data_sent_ipv6, sent);
        } else {
            netdata_update_u64((protocol == AF_INET)?&pport->count_received_ipv4:&pport->count_received_ipv6, 1);
            netdata_update_u64((protocol == AF_INET)?&pport->data_received_ipv4:&pport->data_received_ipv6, received);
        }
    } else {
        if (sent) {
            if (protocol == AF_INET) {
                data.count_sent_ipv4 =  1;
                data.data_sent_ipv4 =  sent;
            } else {
                data.count_sent_ipv6 =  1;
                data.data_sent_ipv6 =  sent;
            }
        } else {
            if (protocol == AF_INET) {
                data.count_received_ipv4 = 1;
                data.data_received_ipv4 = received;
            } else {
                data.count_received_ipv6 = 1;
                data.data_received_ipv6 = received;
            }
        }

        bpf_map_update_elem(ptr, &port, &data, BPF_ANY);
    }
}

static void set_statistic(struct netdata_statistic_t *ns, struct inet_sock *is, size_t sent, size_t received)
{
    __u64 ct = bpf_ktime_get_ns();
    ns->first = ct;
    ns->ct = ct;

    bpf_probe_read(&ns->family, sizeof(u16), &is->sk.__sk_common.skc_family);
    if ( ns->family == AF_INET ) { //AF_INET
        bpf_probe_read(&ns->saddr.addr32[0], sizeof(u32), &is->inet_saddr);
        bpf_probe_read(&ns->daddr.addr32[0], sizeof(u32), &is->inet_daddr);
    }
#if IS_ENABLED(CONFIG_IPV6)
    else if ( ns->family == AF_INET6){
        struct in6_addr *addr6 = &is->sk.sk_v6_rcv_saddr;
        bpf_probe_read(&ns->saddr.addr8,  sizeof(__u8)*16, &addr6->s6_addr);

        addr6 = &is->sk.sk_v6_daddr;
        bpf_probe_read(&ns->daddr.addr8,  sizeof(__u8)*16, &addr6->s6_addr);
    }
#endif

    bpf_probe_read(&ns->dport, sizeof(u16), &is->inet_dport);
    ns->retransmit = 0;
    ns->sent = (__u64)sent;
    ns->recv = (__u64)received;
}

static void netdata_update_global(__u32 key, __u32 value)
{
    u32 *res;
    res = bpf_map_lookup_elem(&tbl_nv_total_stats, &key);
    if (res) {
        netdata_update_u32(res, value) ;
    } else
        bpf_map_update_elem(&tbl_nv_total_stats, &key, &value, BPF_ANY);
}

/************************************************************************************
 *     
 *                                 TCP Section
 *     
 ***********************************************************************************/

SEC("kprobe/tcp_sendmsg")
int trace_tcp_sendmsg(struct pt_regs* ctx)
{
    size_t length = (size_t)PT_REGS_PARM3(ctx);
    struct inet_sock *is = inet_sk((struct sock *)PT_REGS_PARM1(ctx));
    struct netdata_statistic_t data = { };

    netdata_update_global(0, 1);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    struct netdata_statistic_t *ns;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    ns = (struct netdata_statistic_t *) bpf_map_lookup_elem(&tbl_nv_conn_stats, &pid);
    if(ns)
    {
        ns->sent += (__u64)length;
        ns->ct = bpf_ktime_get_ns();
    }
    else
    {
#endif
        set_statistic(&data, is, length, 0);
        data.tgid = (__u32)(pid_tgid & NETDATA_GET_TGID);
        data.protocol = 6;
        data.removeme = 0;

        ns = &data;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
        bpf_map_update_elem(&tbl_nv_conn_stats, &pid, &data, BPF_ANY);
    }

    set_port_stats(&tbl_nv_tcp_stats, ns->dport, (__u64)length, 0, ns->family);
#endif

    /*
    __u32 cpuid = bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &tbl_nv_netdata_stats, cpuid, ns, sizeof(struct netdata_statistic_t));
    */

    return 0;
}

/* CREATE A TABLE TO REGISTRY FAILS
SEC("kretprobe/tcp_sendmsg")
int ret_tcp_sendmsg(struct pt_regs* ctx)
{
    return 0;
}
*/

SEC("kprobe/tcp_cleanup_rbuf")
int netdata_trace_tcp_cleanup_rbuf(struct pt_regs* ctx)
{
    struct netdata_statistic_t data = { };
    struct inet_sock *is = inet_sk((struct sock *)PT_REGS_PARM1(ctx));
    int copied = (int)PT_REGS_PARM2(ctx);

    netdata_update_global(1, 1);
    if ( copied < 0 )
    {
        return 0;
    }


    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    struct netdata_statistic_t *ns;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    ns = (struct netdata_statistic_t *) bpf_map_lookup_elem(&tbl_nv_conn_stats, &pid);
    if(ns)
    {
        ns->recv += (__u64)copied;
        ns->ct = bpf_ktime_get_ns();
    }
    else
    {
#endif
        set_statistic(&data, is, 0, (size_t)copied);
        data.tgid = (__u32)(pid_tgid & NETDATA_GET_TGID);
        data.protocol = 6;
        data.removeme = 0;
        ns = &data;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
        bpf_map_update_elem(&tbl_nv_conn_stats, &pid, &data, BPF_ANY);
    }

    set_port_stats(&tbl_nv_tcp_stats, ns->dport, 0, (__u64)copied, ns->family);
#endif

    /*
    __u32 cpuid = bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &tbl_nv_netdata_stats, cpuid, ns, sizeof(struct netdata_statistic_t));
    */

    return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int netdata_trace_retransmit(struct pt_regs* ctx)
{
    struct netdata_statistic_t data = { };
    struct inet_sock *is = inet_sk((struct sock *)PT_REGS_PARM1(ctx));

    netdata_update_global(2, 1);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    struct netdata_statistic_t *ns;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    ns = (struct netdata_statistic_t *) bpf_map_lookup_elem(&tbl_nv_conn_stats, &pid);
    if(ns)
    {
        ns->retransmit += 1;
        ns->ct = bpf_ktime_get_ns();
    }
    else
    {
#endif
        set_statistic(&data, is, 0, 0);
        data.tgid = (__u32)(pid_tgid & NETDATA_GET_TGID);
        data.protocol = 6;
        data.removeme = 0;
        data.retransmit = 1;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
        bpf_map_update_elem(&tbl_nv_conn_stats, &pid, &data, BPF_ANY);
    }
#endif

    /*
    __u32 cpuid = bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &tbl_nv_netdata_stats, cpuid, &data, sizeof(data));
    */

    return 0;
}

SEC("kprobe/tcp_close")
int netdata_tcp_v4_destroy_sock(struct pt_regs* ctx)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    struct netdata_statistic_t data = { };

    struct netdata_statistic_t *ns;
    ns = (struct netdata_statistic_t *) bpf_map_lookup_elem(&tbl_nv_conn_stats, &pid);
    if(!ns)
    {
       return 0;
    }

    data.first = ns->first;
    data.ct = bpf_ktime_get_ns();
    data.saddr.addr32[0] = ns->saddr.addr32[0];
    data.saddr.addr32[1] = ns->saddr.addr32[1];
    data.saddr.addr32[2] = ns->saddr.addr32[2];
    data.saddr.addr32[3] = ns->saddr.addr32[3];

    data.daddr.addr32[0] = ns->daddr.addr32[0];
    data.daddr.addr32[1] = ns->daddr.addr32[1];
    data.daddr.addr32[2] = ns->daddr.addr32[2];
    data.daddr.addr32[3] = ns->daddr.addr32[3];

    data.dport = ns->dport;
    data.retransmit = ns->retransmit;
    data.sent = ns->sent;
    data.recv = ns->recv;
    data.protocol = ns->protocol;
    data.family = 0;
    data.removeme = 1;

    /*
    __u32 cpuid = bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &tbl_nv_netdata_stats, cpuid, &data, sizeof(data));
    */

    bpf_map_delete_elem(&tbl_nv_conn_stats, &pid);

    netdata_update_global(3, 1);
#endif

    return 0;
}

/************************* UDP *************************/

// We can only get the accurate number of copied bytes from the return value, so we pass our
// sock* pointer from the kprobe to the kretprobe via a map (udp_recv_sock) to get all required info
//
// The same issue exists for TCP, but we can conveniently use the downstream function tcp_cleanup_rbuf


SEC("kprobe/udp_recvmsg")
int trace_udp_recvmsg(struct pt_regs* ctx)
{
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    netdata_update_global(4, 1);
    bpf_map_update_elem(&tbl_nv_udp_conn_stats, &pid_tgid, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/udp_recvmsg")
int trace_udp_ret_recvmsg(struct pt_regs* ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    struct sock **skpp = bpf_map_lookup_elem(&tbl_nv_udp_conn_stats, &pid_tgid);
    if (skpp == 0) 
    {
        return 0;
    }

    struct inet_sock *is = inet_sk((struct sock *)*skpp);
    int copied = (int)PT_REGS_RC(ctx);

    if(copied < 0)
    {
        bpf_map_delete_elem(&tbl_nv_udp_conn_stats, &pid_tgid);
        return 0;
    }

    struct netdata_statistic_t data = { };
    struct netdata_statistic_t *ns;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    ns = (struct netdata_statistic_t *) bpf_map_lookup_elem(&tbl_nv_conn_stats, &pid);
    if(ns)
    {
        ns->recv += (__u64)copied;
    }
    else
    {
#endif
        set_statistic(&data, is, 0, (size_t)copied);
        data.tgid = (__u32)(pid_tgid & NETDATA_GET_TGID);
        data.protocol = 17;
        data.removeme = 0;
        ns = &data;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
        bpf_map_update_elem(&tbl_nv_conn_stats, &pid, &data, BPF_ANY);
    }
    bpf_map_delete_elem(&tbl_nv_udp_conn_stats, &pid_tgid);

    set_port_stats(&tbl_nv_udp_stats, ns->dport, 0, (__u64)copied, ns->family);
#endif

    /*
    __u32 cpuid = bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &tbl_nv_netdata_stats, cpuid, ns, sizeof(struct netdata_statistic_t));
    */

    return 0;
}

SEC("kprobe/udp_sendmsg")
int trace_udp_sendmsg(struct pt_regs* ctx)
{
    struct inet_sock *is = inet_sk((struct sock *)PT_REGS_PARM1(ctx));
    size_t length = (size_t)PT_REGS_PARM3(ctx);
    struct netdata_statistic_t data = { };

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    netdata_update_global(5, 1);

    struct netdata_statistic_t *ns;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    ns = (struct netdata_statistic_t *) bpf_map_lookup_elem(&tbl_nv_conn_stats, &pid);
    if(ns)
    {
        ns->sent += (__u64)length;
        ns->ct = bpf_ktime_get_ns();
    }
    else
    {
#endif
        set_statistic(&data, is, length, 0);
        data.tgid = (__u32)(pid_tgid & NETDATA_GET_TGID);
        data.protocol = 17;
        data.removeme = 0;
        ns = &data;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
        bpf_map_update_elem(&tbl_nv_conn_stats, &pid, &data, BPF_ANY);
    }

    set_port_stats(&tbl_nv_udp_stats, ns->dport, (__u64)length, 0, ns->family);
#endif

    /*
    __u32 cpuid = bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &tbl_nv_netdata_stats, cpuid, ns, sizeof(struct netdata_statistic_t));
    */

    return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
