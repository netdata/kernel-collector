#define KBUILD_MODNAME "dc_kern"
#include <linux/bpf.h>

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "netdata_ebpf.h"

/************************************************************************************
 *
 *                                   Maps Section
 *
 ***********************************************************************************/

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
        __type(value, __u32);
        __uint(max_entries, NETDATA_CONTROLLER_END);
} dcstat_ctrl SEC(".maps");

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

    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&dcstat_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    fill = bpf_map_lookup_elem(&dcstat_pid ,&key);
    if (fill) {
        libnetdata_update_u64(&fill->references, 1);
    } else {
        data.references = 1;
        bpf_map_update_elem(&dcstat_pid, &key, &data, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/d_lookup")
int netdata_d_lookup(struct pt_regs* ctx)
{
    netdata_dc_stat_t *fill, data = {};
    libnetdata_update_global(&dcstat_global, NETDATA_KEY_DC_SLOW, 1);

    int ret = PT_REGS_RC(ctx);

    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&dcstat_ctrl ,&key);
    if (!apps)
        return 0;

    if (*apps == 1) {
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        key = (__u32)(pid_tgid >> 32);
        fill = bpf_map_lookup_elem(&dcstat_pid ,&key);
        if (fill) {
            libnetdata_update_u64(&fill->slow, 1);
        } else {
            data.slow = 1;
            bpf_map_update_elem(&dcstat_pid, &key, &data, BPF_ANY);
        }
    }

    // file not found
    if (ret == 0) {
        libnetdata_update_global(&dcstat_global, NETDATA_KEY_DC_MISS, 1);
        if (*apps == 1) {
            fill = bpf_map_lookup_elem(&dcstat_pid ,&key);
            if (fill) {
                libnetdata_update_u64(&fill->missed, 1);
            } else {
                data.missed = 1;
                bpf_map_update_elem(&dcstat_pid, &key, &data, BPF_ANY);
            }
        }
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

