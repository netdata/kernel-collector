#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "netdata_core.h"
#include "netdata_swap.h"

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
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
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

/***********************************************************************************
 *
 *                               SWAP COMMON
 *
 ***********************************************************************************/

static inline int common_readpage()
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

static inline int common_writepage()
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

/***********************************************************************************
 *
 *                            SWAP SECTION(kprobe)
 *
 ***********************************************************************************/

SEC("kprobe/swap_readpage")
int BPF_KPROBE(netdata_swap_readpage_probe)
{
    return common_readpage();
}

SEC("kprobe/swap_writepage")
int BPF_KPROBE(netdata_swap_writepage_probe)
{
    return common_writepage();
}

/***********************************************************************************
 *
 *                            SWAP SECTION(trampoline)
 *
 ***********************************************************************************/

SEC("fentry/swap_readpage")
int BPF_KPROBE(netdata_swap_readpage_fentry)
{
    return common_readpage();
}

SEC("fentry/swap_writepage")
int BPF_KPROBE(netdata_swap_writepage_fentry)
{
    return common_writepage();
}

char _license[] SEC("license") = "GPL";

