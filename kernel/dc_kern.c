#define KBUILD_MODNAME "dc_kern"

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
 *                                   Maps Section
 *
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_DIRECTORY_CACHE_END);
} dcstat_global SEC(".maps");

struct {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    __uint(type, BPF_MAP_TYPE_HASH);
#else
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#endif
    __type(key, __u32);
    __type(value, netdata_dc_stat_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} dcstat_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} dcstat_ctrl SEC(".maps");

#else

struct bpf_map_def SEC("maps") dcstat_global = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_DIRECTORY_CACHE_END
};

struct bpf_map_def SEC("maps") dcstat_pid = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(netdata_dc_stat_t),
    .max_entries = PID_MAX_DEFAULT
};

struct bpf_map_def SEC("maps") dcstat_ctrl = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_CONTROLLER_END
};

#endif

/************************************************************************************
 *
 *                                   Probe Section
 *
 ***********************************************************************************/

SEC("kprobe/lookup_fast")
int netdata_lookup_fast(struct pt_regs* ctx)
{
    netdata_dc_stat_t *fill, data = {};
    libnetdata_update_global(&dcstat_global, NETDATA_KEY_DC_REFERENCE, 1);

    __u32 key = 0;
    if (!monitor_apps(&dcstat_ctrl))
        return 0;

    fill = netdata_get_pid_structure(&key, &dcstat_ctrl, &dcstat_pid);
    if (fill) {
        libnetdata_update_u64(&fill->references, 1);
    } else {
        data.references = 1;
        bpf_map_update_elem(&dcstat_pid, &key, &data, BPF_ANY);

        libnetdata_update_global(&dcstat_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

SEC("kretprobe/d_lookup")
int netdata_d_lookup(struct pt_regs* ctx)
{
    netdata_dc_stat_t *fill, data = {};
    libnetdata_update_global(&dcstat_global, NETDATA_KEY_DC_SLOW, 1);

    int ret = PT_REGS_RC(ctx);

    __u32 key = 0;
    if (!monitor_apps(&dcstat_ctrl))
        return 0;

    fill = netdata_get_pid_structure(&key, &dcstat_ctrl, &dcstat_pid);
    if (fill) {
        libnetdata_update_u64(&fill->slow, 1);
    } else {
        data.slow = 1;
        bpf_map_update_elem(&dcstat_pid, &key, &data, BPF_ANY);

        libnetdata_update_global(&dcstat_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
    }

    // file not found
    if (ret == 0) {
        libnetdata_update_global(&dcstat_global, NETDATA_KEY_DC_MISS, 1);
        fill = netdata_get_pid_structure(&key, &dcstat_ctrl, &dcstat_pid);
        if (fill) {
            libnetdata_update_u64(&fill->missed, 1);
        } else {
            data.missed = 1;
            bpf_map_update_elem(&dcstat_pid, &key, &data, BPF_ANY);

            libnetdata_update_global(&dcstat_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
        }
    }

    return 0;
}

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
int netdata_release_task_dc(struct pt_regs* ctx)
{
    netdata_dc_stat_t *removeme;
    __u32 key = 0;
    if (!monitor_apps(&dcstat_ctrl))
        return 0;

    removeme = netdata_get_pid_structure(&key, &dcstat_ctrl, &dcstat_pid);
    if (removeme) {
        bpf_map_delete_elem(&dcstat_pid, &key);

        libnetdata_update_global(&dcstat_ctrl, NETDATA_CONTROLLER_PID_TABLE_DEL, 1);
    }

    return 0;
}


char _license[] SEC("license") = "GPL";

