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

NETDATA_BPF_PERCPU_ARRAY_DEF(dcstat_global, __u32, __u64, NETDATA_DIRECTORY_CACHE_END);
NETDATA_BPF_HASH_DEF(dcstat_pid, __u32, netdata_dc_stat_t, PID_MAX_DEFAULT);
NETDATA_BPF_PERCPU_ARRAY_DEF(dcstat_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

static __always_inline void netdata_dc_update_existing(__u32 *field)
{
    if (field)
        libnetdata_update_u32(field, 1);
}

static __always_inline void netdata_dc_create_new_entry(__u32 *field, __u32 tgid)
{
    netdata_dc_stat_t data = {};

    data.ct = bpf_ktime_get_ns();
    libnetdata_update_uid_gid(&data.uid, &data.gid);
    data.tgid = tgid;

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
    bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
    data.name[0] = '\0';
#endif

    __u32 key = 0;
    if (field)
        *field = 1;
    bpf_map_update_elem(&dcstat_pid, &key, &data, BPF_ANY);

    libnetdata_update_global(&dcstat_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
}

/************************************************************************************
 *
 *                                   Probe Section
 *
 ***********************************************************************************/

SEC("kprobe/lookup_fast")
int netdata_lookup_fast(struct pt_regs* ctx)
{
    libnetdata_update_global(&dcstat_global, NETDATA_KEY_DC_REFERENCE, 1);

    if (!monitor_apps(&dcstat_ctrl))
        return 0;

    netdata_dc_stat_t *fill, data = {};
    __u32 key = 0;
    __u32 tgid = 0;

    fill = netdata_get_pid_structure(&key, &tgid, &dcstat_ctrl, &dcstat_pid);
    if (fill) {
        netdata_dc_update_existing(&fill->references);
        return 0;
    }

    netdata_dc_create_new_entry(&data.references, tgid);

    return 0;
}

SEC("kretprobe/d_lookup")
int netdata_d_lookup(struct pt_regs* ctx)
{
    int ret = PT_REGS_RC(ctx);

    libnetdata_update_global(&dcstat_global, NETDATA_KEY_DC_SLOW, 1);

    if (!monitor_apps(&dcstat_ctrl))
        return 0;

    netdata_dc_stat_t *fill, data = {};
    __u32 key = 0;
    __u32 tgid = 0;

    fill = netdata_get_pid_structure(&key, &tgid, &dcstat_ctrl, &dcstat_pid);
    if (fill) {
        netdata_dc_update_existing(&fill->slow);
    } else {
        netdata_dc_create_new_entry(&data.slow, tgid);
    }

    if (ret == 0) {
        libnetdata_update_global(&dcstat_global, NETDATA_KEY_DC_MISS, 1);
        fill = netdata_get_pid_structure(&key, &tgid, &dcstat_ctrl, &dcstat_pid);
        if (fill)
            netdata_dc_update_existing(&fill->missed);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

