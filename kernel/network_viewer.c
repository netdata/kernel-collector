#define KBUILD_MODNAME "network_viewer"
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
#include "netdata_ebpf.h"

/************************************************************************************
 *     
 *                              Hash Table Section
 *     
 ***********************************************************************************/

/**
 * Union used to store ip addresses
 */
union netdata_ip {
    __u8 addr8[16];
    __u16 addr16[8];
    __u32 addr32[4];
};

/**
 * Structure to store socket information
 */
typedef struct netdata_socket {
    __u64 pid_tgid;
    __u64 first;
    __u64 ct;
    __u16 retransmit; //It is never used with UDP
    __u64 sent;
    __u64 recv;
    __u8 protocol; //Should this to be in the index?
    __u8 removeme;
} netdata_socket_t;

/**
 * Index used togethre previous structure
 */
typedef struct netdata_socket_idx {
    __u32 pid;
    union netdata_ip saddr;
    union netdata_ip daddr;
    __u16 dport;
} netdata_socket_idx_t;

/**
 * Bandwidth information, the index for this structure is the TGID
 */
typedef struct netdata_bandwidth {
    __u64 first;
    __u64 ct;
    __u64 sent;
    __u64 received;
    __u8 removed;
} netdata_bandwidth_t;

/**
 * Bandwidth hash table
 *
 */
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

/**
 * IPV4 hash table
 *
 */
struct bpf_map_def SEC("maps") tbl_conn_ipv4_stats = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))    
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif    
    .key_size = sizeof(netdata_socket_idx_t),
    .value_size = sizeof(netdata_socket_t),
    .max_entries = 65536
};

/**
 * IPV6 hash table
 *
 */
struct bpf_map_def SEC("maps") tbl_conn_ipv6_stats = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))    
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif    
    .key_size = sizeof(netdata_socket_idx_t),
    .value_size = sizeof(netdata_socket_t),
    .max_entries = 65536
};


/**
 * UDP hash table, this table is necessry to collect the 
 * correct size. More details inside  UDP section.
 */
struct bpf_map_def SEC("maps") tbl_nv_udp_conn_stats = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))    
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif    
    .key_size = sizeof(__u64),
    .value_size = sizeof(void *),
    .max_entries = 8192
};

/*
 * Hash table used to create charts based in calls.
 *
*/
struct bpf_map_def SEC("maps") tbl_sock_total_stats = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries =  NETDATA_SOCKET_COUNTER
};

/************************************************************************************
 *     
 *                                 Common Section
 *     
 ***********************************************************************************/

/**
 * Function used to update 64 bit values and avoid overflow
 */
static void netdata_update_u64(u64 *res, u64 value)
{
    if ( (0xFFFFFFFFFFFFFFFF - *res) <= value)
        *res = value;
    else
        *res += value;
}

/*
 * Update hash table tbl_sock_total_stats
*/
static void netdata_update_global(__u32 key, __u64 value)
{
    u64 *res;
    res = bpf_map_lookup_elem(&tbl_sock_total_stats, &key);
    if (res) {
        netdata_update_u64(res, value) ;
    } else {
        bpf_map_update_elem(&tbl_sock_total_stats, &key, &value, BPF_NOEXIST);
    }
}

/**
 * Set Index value
 *
 * Read information from socket to update the index.
 */
static __u16 set_idx_value(netdata_socket_idx_t *nsi, struct inet_sock *is, uint32_t pid)
{
    __u16 family;

    nsi->pid = pid;
    //Read Family
    bpf_probe_read(&family, sizeof(u16), &is->sk.__sk_common.skc_family);
    //Read source and destination IPs
    if ( family == AF_INET ) { //AF_INET
        bpf_probe_read(&nsi->saddr.addr32[0], sizeof(u32), &is->inet_saddr);
        bpf_probe_read(&nsi->daddr.addr32[0], sizeof(u32), &is->inet_daddr);
    }
    // Check necessary according https://elixir.bootlin.com/linux/v5.6.14/source/include/net/sock.h#L199
#if IS_ENABLED(CONFIG_IPV6)
    else if ( family == AF_INET6 ){
        struct in6_addr *addr6 = &is->sk.sk_v6_rcv_saddr;
        bpf_probe_read(&nsi->saddr.addr8,  sizeof(__u8)*16, &addr6->s6_addr);

        addr6 = &is->sk.sk_v6_daddr;
        bpf_probe_read(&nsi->daddr.addr8,  sizeof(__u8)*16, &addr6->s6_addr);
    }
#endif

    //Read destination port
    bpf_probe_read(&nsi->dport, sizeof(u16), &is->inet_dport);

    return family;
}

/**
 * Update time and bytes sent and received
 */
static void update_socket_stats(netdata_socket_t *ptr, __u64 sent, __u64 received)
{
    ptr->ct = bpf_ktime_get_ns();

    netdata_update_u64(&ptr->sent, sent);
    netdata_update_u64(&ptr->recv, received);
}

/**
 * Reset socket stat when PID is not associated more with previous TGID
 */
static void reset_socket_stats(netdata_socket_t *val, __u64 sent, __u64 received)
{
    val->first = bpf_ktime_get_ns();
    val->ct = val->first;
    val->retransmit = 0;
    val->sent = sent;
    val->recv = received;
    val->removeme = 0;
}

/**
 * Update the table for the index idx
 */
static void update_socket_table(struct bpf_map_def *tbl, netdata_socket_idx_t *idx, __u64 sent, __u64 received, __u64 pid_tgid, __u8 protocol)
{
    netdata_socket_t *val;
    netdata_socket_t data = { };

    val = (netdata_socket_t *) bpf_map_lookup_elem(tbl, idx);
    if (val) {
        if ( val->pid_tgid != pid_tgid) {
            val->pid_tgid = pid_tgid;
            reset_socket_stats(val, sent, received);
        } else {
            update_socket_stats(val, sent, received);
        }
    } else {
        data.pid_tgid = pid_tgid;
        data.first = bpf_ktime_get_ns();
        update_socket_stats(&data, sent, received);

        bpf_map_update_elem(tbl, &idx, &data, BPF_ANY);
    }
}

/**
 * Update the table for the specified PID
 */
static void update_pid_stats(__u32 pid,__u64 sent, __u64 received)
{
    netdata_bandwidth_t *b;
    netdata_bandwidth_t data = { };

    b = (netdata_bandwidth_t *) bpf_map_lookup_elem(&tbl_bandwidth, &pid);
    if (b) {
        b->ct = bpf_ktime_get_ns();
        netdata_update_u64(&b->sent, sent);
        netdata_update_u64(&b->received, received);
    } else {
        data.first = bpf_ktime_get_ns();
        data.ct = data.first;
        data.sent = sent;
        data.received = received;

        bpf_map_update_elem(&tbl_bandwidth, &pid, &data, BPF_ANY);
    }
}


/************************************************************************************
 *     
 *                                 TCP Section
 *     
 ***********************************************************************************/

/**
 * https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/tcp.c#L1436
 */
#if NETDATASEL < 2
SEC("kretprobe/tcp_sendmsg")
#else
SEC("kprobe/tcp_sendmsg")
#endif
int netdata_tcp_sendmsg(struct pt_regs* ctx)
{
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    __u16 family;
    netdata_socket_idx_t idx = { };
    struct bpf_map_def *tbl;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    size_t sent = (size_t)PT_REGS_PARM3(ctx);
    struct inet_sock *is = inet_sk((struct sock *)PT_REGS_PARM1(ctx));

    netdata_update_global(NETDATA_KEY_CALLS_TCP_SENDMSG, 1);

    family = set_idx_value(&idx, is, pid);
    tbl = (family == AF_INET6)?&tbl_conn_ipv6_stats:&tbl_conn_ipv4_stats;

    netdata_update_global(NETDATA_KEY_BYTES_TCP_SENDMSG, (__u64)sent);
    update_socket_table(tbl, &idx, (__u64) sent, 0, pid_tgid, 6);

    update_pid_stats(tgid, (__u64) sent, 0);

#if NETDATASEL < 2
    if (ret < 0) {
        netdata_update_global(NETDATA_KEY_ERROR_TCP_SENDMSG, 1);
    }    
#endif

    return 0;
}

/**
 * https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/tcp.c#L1528
 */
SEC("kprobe/tcp_cleanup_rbuf")
int netdata_tcp_cleanup_rbuf(struct pt_regs* ctx)
{
    __u16 family;
    netdata_socket_idx_t idx = { };
    struct bpf_map_def *tbl;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    int copied = (int)PT_REGS_PARM2(ctx);
    struct inet_sock *is = inet_sk((struct sock *)PT_REGS_PARM1(ctx));

    netdata_update_global(NETDATA_KEY_CALLS_TCP_CLEANUP_RBUF, 1);
    if (copied < 0) {
        netdata_update_global(NETDATA_KEY_ERROR_TCP_CLEANUP_RBUF, 1);
        return 0;
    }

    family = set_idx_value(&idx, is, pid);
    tbl = (family == AF_INET6)?&tbl_conn_ipv6_stats:&tbl_conn_ipv4_stats;

    netdata_update_global(NETDATA_KEY_BYTES_TCP_CLEANUP_RBUF, (__u64) copied);
    update_socket_table(tbl, &idx, 0, (__u64) copied, pid_tgid, 6);

    update_pid_stats(tgid, 0, (__u64) copied);

    return 0;
}

/**
 * https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/tcp.c#L2351
 */
SEC("kprobe/tcp_close")
int netdata_tcp_close(struct pt_regs* ctx)
{
    __u16 family;
    netdata_socket_idx_t idx = { };
    struct bpf_map_def *tbl;
    netdata_socket_t *val;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    struct inet_sock *is = inet_sk((struct sock *)PT_REGS_PARM1(ctx));

    netdata_update_global(NETDATA_KEY_CALLS_TCP_CLOSE, 1);

    family =  set_idx_value(&idx, is, pid);
    tbl = (family == AF_INET6)?&tbl_conn_ipv6_stats:&tbl_conn_ipv4_stats;
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

/* We can only get the accurate number of copied bytes from the return value, so we pass our
 * sock* pointer from the kprobe to the kretprobe via a map (udp_recv_sock) to get all required info
 *
 * The same issue exists for TCP, but we can conveniently use the downstream function tcp_cleanup_rbuf
*/ 

/**
 * https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/udp.c#L1726
 */
SEC("kprobe/udp_recvmsg")
int trace_udp_recvmsg(struct pt_regs* ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);

    bpf_map_update_elem(&tbl_nv_udp_conn_stats, &pid_tgid, &sk, BPF_ANY);
    netdata_update_global(NETDATA_KEY_CALLS_UDP_RECVMSG, 1);

    return 0;
}

/**
 * https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/udp.c#L1726
 */
SEC("kretprobe/udp_recvmsg")
int trace_udp_ret_recvmsg(struct pt_regs* ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    struct bpf_map_def *tbl;

    __u16 family;
    netdata_socket_idx_t idx = { };

    struct sock **skpp = bpf_map_lookup_elem(&tbl_nv_udp_conn_stats, &pid_tgid);
    if (skpp == 0) {
        return 0;
    }

    struct inet_sock *is = inet_sk((struct sock *)*skpp);
    int copied = (int)PT_REGS_RC(ctx);

    if (copied < 0) {
        netdata_update_global(NETDATA_KEY_ERROR_UDP_RECVMSG, 1);
        bpf_map_delete_elem(&tbl_nv_udp_conn_stats, &pid_tgid);
        return 0;
    }

    family =  set_idx_value(&idx, is, pid);
    tbl = (family == AF_INET6)?&tbl_conn_ipv6_stats:&tbl_conn_ipv4_stats;

    netdata_update_global(NETDATA_KEY_BYTES_UDP_RECVMSG, (__u64) copied);
    update_socket_table(tbl, &idx, 0, (__u64) copied, pid_tgid, 17);

    update_pid_stats(tgid, 0, (__u64) copied);

    return 0;
}

/**
 * https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/udp.c#L965
 */
#if NETDATASEL < 2
SEC("kretprobe/udp_sendmsg")
#else
SEC("kprobe/udp_sendmsg")
#endif
int trace_udp_sendmsg(struct pt_regs* ctx)
{
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    struct bpf_map_def *tbl;

    __u16 family;
    size_t sent = (size_t)PT_REGS_PARM3(ctx);
    netdata_socket_idx_t idx = { };
    struct inet_sock *is = inet_sk((struct sock *)PT_REGS_PARM1(ctx));

    netdata_update_global(NETDATA_KEY_CALLS_UDP_SENDMSG, 1);

    family =  set_idx_value(&idx, is, pid);
    tbl = (family == AF_INET6)?&tbl_conn_ipv6_stats:&tbl_conn_ipv4_stats;

    update_socket_table(tbl, &idx, (__u64) sent, 0, pid_tgid, 17);

    netdata_update_global(NETDATA_KEY_BYTES_UDP_SENDMSG, (__u64) sent);
    update_pid_stats(tgid, (__u64) sent, 0);

#if NETDATASEL < 2
    if (ret < 0) {
        netdata_update_global(NETDATA_KEY_ERROR_UDP_SENDMSG, 1);
    }
#endif

    return 0;
}

/************************************************************************************
 *     
 *                                 Process Section
 *     
 ***********************************************************************************/

/**
 * https://elixir.bootlin.com/linux/latest/source/kernel/exit.c#L711
 */
SEC("kprobe/do_exit")
int netdata_sys_exit(struct pt_regs* ctx)
{
    netdata_bandwidth_t *b;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    //Am I the child?
    if ( pid != tgid )
        return 0;


    //Remove PID from table
    b = (netdata_bandwidth_t *) bpf_map_lookup_elem(&tbl_bandwidth, &tgid);
    if (b) {
        b->removed = 1;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;

