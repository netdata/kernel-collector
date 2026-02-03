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

NETDATA_BPF_PERCPU_ARRAY_DEF(tbl_swap, __u32, __u64, NETDATA_SWAP_END);
NETDATA_BPF_HASH_DEF(tbl_pid_swap, __u32, netdata_swap_access_t, PID_MAX_DEFAULT);
NETDATA_BPF_ARRAY_DEF(swap_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

/************************************************************************************
 *
 *                               SWAP SECTION
 *
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(6,7,255))
SEC("kprobe/swap_read_folio")
#else
SEC("kprobe/swap_readpage")
#endif
int netdata_swap_readpage(struct pt_regs* ctx)
{
    netdata_swap_access_t data = {};

    libnetdata_update_global(&tbl_swap, NETDATA_KEY_SWAP_READPAGE_CALL, 1);

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&swap_ctrl))
        return 0;

    netdata_swap_access_t *fill = netdata_get_pid_structure(&key, &tgid, &swap_ctrl, &tbl_pid_swap);
    if (fill) {
        libnetdata_update_u32(&fill->read, 1);
    } else {
        data.ct = bpf_ktime_get_ns();
        libnetdata_update_uid_gid(&data.uid, &data.gid);
        data.tgid = tgid;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif

        data.read = 1;
        bpf_map_update_elem(&tbl_pid_swap, &key, &data, BPF_ANY);

        libnetdata_update_global(&swap_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,16,0))
SEC("kprobe/__swap_writepage")
#else
SEC("kprobe/swap_writepage")
#endif
int netdata_swap_writepage(struct pt_regs* ctx)
{
    netdata_swap_access_t data = {};

    libnetdata_update_global(&tbl_swap, NETDATA_KEY_SWAP_WRITEPAGE_CALL, 1);

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&swap_ctrl))
        return 0;

    netdata_swap_access_t *fill = netdata_get_pid_structure(&key, &tgid, &swap_ctrl, &tbl_pid_swap);
    if (fill) {
        libnetdata_update_u32(&fill->write, 1);
    } else {
        data.ct = bpf_ktime_get_ns();
        libnetdata_update_uid_gid(&data.uid, &data.gid);
        data.tgid = tgid;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif

        data.write = 1;
        bpf_map_update_elem(&tbl_pid_swap, &key, &data, BPF_ANY);

        libnetdata_update_global(&swap_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

