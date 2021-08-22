#define KBUILD_MODNAME "swap_netdata"
#include <linux/bpf.h>

#include <linux/threads.h>

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "netdata_ebpf.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, __u32);
        __type(value, __u64);
        __uint(max_entries, NETDATA_SWAP_END);
} tbl_swap  SEC(".maps");

struct {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
        __uint(type, BPF_MAP_TYPE_HASH);
#else
        __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#endif
        __type(key, __u32);
        __type(value, netdata_swap_access_t);
        __uint(max_entries, PID_MAX_DEFAULT);
} tbl_pid_swap SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, __u32);
        __uint(max_entries, NETDATA_CONTROLLER_END);
} swap_ctrl SEC(".maps");

/************************************************************************************
 *
 *                               SYNC SECTION
 *
 ***********************************************************************************/

SEC("kprobe/swap_readpage")
int netdata_swap_readpage(struct pt_regs* ctx)
{
    netdata_swap_access_t data = {};

    libnetdata_update_global(&tbl_swap, NETDATA_KEY_SWAP_READPAGE_CALL, 1);

    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&swap_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    netdata_swap_access_t *fill = bpf_map_lookup_elem(&tbl_pid_swap ,&key);
    if (fill) {
        libnetdata_update_u64(&fill->read, 1);
    } else {
        data.read = 1;
        bpf_map_update_elem(&tbl_pid_swap, &key, &data, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/swap_writepage")
int netdata_swap_writepage(struct pt_regs* ctx)
{
    netdata_swap_access_t data = {};

    libnetdata_update_global(&tbl_swap, NETDATA_KEY_SWAP_WRITEPAGE_CALL, 1);

    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&swap_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    netdata_swap_access_t *fill = bpf_map_lookup_elem(&tbl_pid_swap ,&key);
    if (fill) {
        libnetdata_update_u64(&fill->write, 1);
    } else {
        data.write = 1;
        bpf_map_update_elem(&tbl_pid_swap, &key, &data, BPF_ANY);
    }

    return 0;
}

/************************************************************************************
 *
 *                             END SYNC SECTION
 *
 ***********************************************************************************/

char _license[] SEC("license") = "GPL";

