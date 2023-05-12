#define KBUILD_MODNAME "swap_netdata"

#include <linux/threads.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "netdata_ebpf.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
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
    __type(value, __u64);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} swap_ctrl SEC(".maps");
#else
struct bpf_map_def SEC("maps") tbl_swap = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_SWAP_END
};

struct bpf_map_def SEC("maps") tbl_pid_swap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(netdata_swap_access_t),
    .max_entries = PID_MAX_DEFAULT
};

struct bpf_map_def SEC("maps") swap_ctrl = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_CONTROLLER_END
};
#endif

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

    __u32 key = 0;
    if (!monitor_apps(&swap_ctrl))
        return 0;

    netdata_swap_access_t *fill = netdata_get_pid_structure(&key, &swap_ctrl, &tbl_pid_swap);
    if (fill) {
        libnetdata_update_u64(&fill->read, 1);
    } else {
        data.read = 1;
        bpf_map_update_elem(&tbl_pid_swap, &key, &data, BPF_ANY);

        libnetdata_update_global(&swap_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

SEC("kprobe/swap_writepage")
int netdata_swap_writepage(struct pt_regs* ctx)
{
    netdata_swap_access_t data = {};

    libnetdata_update_global(&tbl_swap, NETDATA_KEY_SWAP_WRITEPAGE_CALL, 1);

    __u32 key = 0;
    if (!monitor_apps(&swap_ctrl))
        return 0;

    netdata_swap_access_t *fill = netdata_get_pid_structure(&key, &swap_ctrl, &tbl_pid_swap);
    if (fill) {
        libnetdata_update_u64(&fill->write, 1);
    } else {
        data.write = 1;
        bpf_map_update_elem(&tbl_pid_swap, &key, &data, BPF_ANY);

        libnetdata_update_global(&swap_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

/************************************************************************************
 *
 *                             END SYNC SECTION
 *
 ***********************************************************************************/

/**
 * Release task
 *
 * Removing a pid when it's no longer needed helps us reduce the default
 * size used with our tables.
 *
 * When a process stops so fast that apps.plugin or cgroup.plugin cannot detect it, we don't show
 * the information about the process, so it is safe to remove the information about the table.
 */
SEC("kprobe/release_task")
int netdata_release_task_swap(struct pt_regs* ctx)
{
    netdata_cachestat_t *removeme;
    __u32 key = 0;
    if (!monitor_apps(&swap_ctrl))
        return 0;

    removeme = netdata_get_pid_structure(&key, &swap_ctrl, &tbl_pid_swap);
    if (removeme) {
        bpf_map_delete_elem(&tbl_pid_swap, &key);

        libnetdata_update_global(&swap_ctrl, NETDATA_CONTROLLER_PID_TABLE_DEL, 1);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

