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
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    __uint(type, BPF_MAP_TYPE_HASH);
#else
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#endif
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
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    __uint(type, BPF_MAP_TYPE_HASH);
#else
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#endif
    __type(key, netdata_socket_idx_t);
    __type(value, netdata_socket_t);
    __uint(max_entries, 65536);
} tbl_conn_ipv4 SEC(".maps");

struct {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    __uint(type, BPF_MAP_TYPE_HASH);
#else
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#endif
    __type(key, netdata_socket_idx_t);
    __type(value, netdata_socket_t);
    __uint(max_entries, 65536);
} tbl_conn_ipv6 SEC(".maps");

struct {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    __uint(type, BPF_MAP_TYPE_HASH);
#else
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#endif
    __type(key, __u64);
    __type(value, void *);
    __uint(max_entries, 8192);
} tbl_nv_udp SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, netdata_passive_connection_idx_t);
    __type(value, netdata_passive_connection_t);
    __uint(max_entries, 1024);
} tbl_lports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} socket_ctrl SEC(".maps");

#else

struct bpf_map_def SEC("maps") tbl_bandwidth = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(netdata_bandwidth_t),
    .max_entries = PID_MAX_DEFAULT
};

struct bpf_map_def SEC("maps") tbl_global_sock = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries =  NETDATA_SOCKET_COUNTER
};

struct bpf_map_def SEC("maps") tbl_conn_ipv4 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(netdata_socket_idx_t),
    .value_size = sizeof(netdata_socket_t),
    .max_entries = 65536
};

struct bpf_map_def SEC("maps") tbl_conn_ipv6 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(netdata_socket_idx_t),
    .value_size = sizeof(netdata_socket_t),
    .max_entries = 65536
};

struct bpf_map_def SEC("maps") tbl_nv_udp = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(void *),
    .max_entries = 8192
};

struct bpf_map_def SEC("maps") tbl_lports = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(netdata_passive_connection_idx_t),
    .value_size = sizeof(netdata_passive_connection_t),
    .max_entries =  1024
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

#if NETDATASEL < 2
SEC("kretprobe/tcp_sendmsg")
#else
SEC("kprobe/tcp_sendmsg")
#endif
int netdata_tcp_sendmsg(struct pt_regs* ctx)
{
    return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int netdata_tcp_retransmit_skb(struct pt_regs* ctx)
{
    return 0;
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/tcp.c#L1528
SEC("kprobe/tcp_cleanup_rbuf")
int netdata_tcp_cleanup_rbuf(struct pt_regs* ctx)
{
    return 0;
}

SEC("kprobe/tcp_close")
int netdata_tcp_close(struct pt_regs* ctx)
{
    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/tcp_v4_connect")
#else
SEC("kprobe/tcp_v4_connect")
#endif
int netdata_tcp_v4_connect(struct pt_regs* ctx)
{
    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/tcp_v6_connect")
#else
SEC("kprobe/tcp_v6_connect")
#endif
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

SEC("kretprobe/udp_recvmsg")
int trace_udp_ret_recvmsg(struct pt_regs* ctx)
{
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
    return 0;
}

/************************************************************************************
 *
 *                           CLEAN UP SECTION
 *
 ***********************************************************************************/

/**
 * Release task socket
 *
 * Removing a socket when it's no longer needed helps us reduce the default
 * size used with our tables.
 *
 * When a process stops so fast that apps.plugin or cgroup.plugin cannot detect it, we don't show
 * the information about the process, so it is safe to remove the information about the socket.
 */
SEC("kprobe/release_task")
int netdata_release_task_socket(struct pt_regs* ctx)
{
    netdata_bandwidth_t *removeme;
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&socket_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    removeme = (netdata_bandwidth_t *) netdata_get_pid_structure(&key, &socket_ctrl, &tbl_bandwidth);
    if (removeme)
        bpf_map_delete_elem(&tbl_bandwidth, &key);

    return 0;
}

char _license[] SEC("license") = "GPL";

