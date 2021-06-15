#define KBUILD_MODNAME "dc_kern"
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/threads.h>

#include "bpf_helpers.h"
#include "netdata_ebpf.h"

/************************************************************************************
 *
 *                                   Maps Section
 *
 ***********************************************************************************/

struct bpf_map_def SEC("maps") dcstat_global = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_DIRECTORY_CACHE_END
};

struct bpf_map_def SEC("maps") dcstat_pid = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)) 
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u32),
    .value_size = sizeof(netdata_dc_stat_t),
    .max_entries = PID_MAX_DEFAULT
};

struct bpf_map_def SEC("maps") dcstat_ctrl = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = NETDATA_CONTROLLER_END
};

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

    __u32 pid = 0;
    __u32 *apps = bpf_map_lookup_elem(&dcstat_ctrl ,&pid);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    pid = (__u32)(pid_tgid >> 32);
    fill = bpf_map_lookup_elem(&dcstat_pid ,&pid);
    if (fill) {
        libnetdata_update_u64(&fill->references, 1);
    } else {
        data.references = 1;
        bpf_map_update_elem(&dcstat_pid, &pid, &data, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/d_lookup")
int netdata_d_lookup(struct pt_regs* ctx)
{
    netdata_dc_stat_t *fill, data = {};
    libnetdata_update_global(&dcstat_global, NETDATA_KEY_DC_SLOW, 1);

    int ret = PT_REGS_RC(ctx);

    __u32 pid = 0;
    __u32 *apps = bpf_map_lookup_elem(&dcstat_ctrl ,&pid);
    if (!apps)
        return 0;

    if (*apps == 1) {
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        pid = (__u32)(pid_tgid >> 32);
        fill = bpf_map_lookup_elem(&dcstat_pid ,&pid);
        if (fill) {
            libnetdata_update_u64(&fill->slow, 1);
        } else {
            data.slow = 1;
            bpf_map_update_elem(&dcstat_pid, &pid, &data, BPF_ANY);
        }
    }

    // file not found
    if (ret == 0) {
        libnetdata_update_global(&dcstat_global, NETDATA_KEY_DC_MISS, 1);
        if (*apps == 1) {
            fill = bpf_map_lookup_elem(&dcstat_pid ,&pid);
            if (fill) {
                libnetdata_update_u64(&fill->missed, 1);
            } else {
                data.missed = 1;
                bpf_map_update_elem(&dcstat_pid, &pid, &data, BPF_ANY);
            }
        }
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

