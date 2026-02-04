#define KBUILD_MODNAME "nfs_netdata"
#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0))
#include <linux/genhd.h>
#endif

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
 *                                 MAP Section
 *
 ***********************************************************************************/

NETDATA_BPF_PERCPU_ARRAY_DEF(tbl_nfs, __u32, __u64, NETDATA_FS_MAX_ELEMENTS);
NETDATA_BPF_HASH_DEF(tmp_nfs, __u32, __u64, 4192);
NETDATA_BPF_ARRAY_DEF(nfs_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

/************************************************************************************
 *
 *                                 Helper Functions
 *
 ***********************************************************************************/

static __always_inline void netdata_nfs_store_bin(__u32 bin, __u32 selection)
{
    __u32 idx = selection * NETDATA_FS_MAX_BINS + bin;
    if (idx >= NETDATA_FS_MAX_ELEMENTS)
        return;

    __u64 *fill = bpf_map_lookup_elem(&tbl_nfs, &idx);
    if (fill) {
        libnetdata_update_u64(fill, 1);
        return;
    }

    bpf_map_update_elem(&tbl_nfs, &idx, &(unsigned long long){1}, BPF_ANY);
    libnetdata_update_global(&nfs_ctrl, NETDATA_CONTROLLER_TEMP_TABLE_DEL, 1);
}

static __always_inline int netdata_nfs_ret(struct pt_regs *ctx, __u32 selector)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    __u64 *fill = bpf_map_lookup_elem(&tmp_nfs, &pid);
    if (!fill)
        return 0;

    __u64 data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_nfs, &pid);

    if ((s64)data < 0)
        return 0;

    data /= 1000;
    __u32 bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    netdata_nfs_store_bin(bin, selector);

    return 0;
}

/************************************************************************************
 *
 *                                 ENTRY Section
 *
 ***********************************************************************************/

SEC("kprobe/nfs_file_read")
int netdata_nfs_file_read(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&tmp_nfs, &pid, &(unsigned long long){bpf_ktime_get_ns()}, BPF_ANY);
    libnetdata_update_global(&nfs_ctrl, NETDATA_CONTROLLER_TEMP_TABLE_ADD, 1);
    return 0;
}

SEC("kprobe/nfs_file_write")
int netdata_nfs_file_write(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&tmp_nfs, &pid, &(unsigned long long){bpf_ktime_get_ns()}, BPF_ANY);
    libnetdata_update_global(&nfs_ctrl, NETDATA_CONTROLLER_TEMP_TABLE_ADD, 1);
    return 0;
}

SEC("kprobe/nfs_file_open")
int netdata_nfs_file_open(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&tmp_nfs, &pid, &(unsigned long long){bpf_ktime_get_ns()}, BPF_ANY);
    libnetdata_update_global(&nfs_ctrl, NETDATA_CONTROLLER_TEMP_TABLE_ADD, 1);
    return 0;
}

SEC("kprobe/nfs4_file_open")
int netdata_nfs4_file_open(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&tmp_nfs, &pid, &(unsigned long long){bpf_ktime_get_ns()}, BPF_ANY);
    libnetdata_update_global(&nfs_ctrl, NETDATA_CONTROLLER_TEMP_TABLE_ADD, 1);
    return 0;
}

SEC("kprobe/nfs_getattr")
int netdata_nfs_getattr(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&tmp_nfs, &pid, &(unsigned long long){bpf_ktime_get_ns()}, BPF_ANY);
    libnetdata_update_global(&nfs_ctrl, NETDATA_CONTROLLER_TEMP_TABLE_ADD, 1);
    return 0;
}

/************************************************************************************
 *
 *                                 END Section
 *
 ***********************************************************************************/

SEC("kretprobe/nfs_file_read")
int netdata_ret_nfs_file_read(struct pt_regs *ctx)
{
    return netdata_nfs_ret(ctx, NETDATA_KEY_CALLS_READ);
}

SEC("kretprobe/nfs_file_write")
int netdata_ret_nfs_file_write(struct pt_regs *ctx)
{
    return netdata_nfs_ret(ctx, NETDATA_KEY_CALLS_WRITE);
}

SEC("kretprobe/nfs_file_open")
int netdata_ret_nfs_file_open(struct pt_regs *ctx)
{
    return netdata_nfs_ret(ctx, NETDATA_KEY_CALLS_OPEN);
}

SEC("kretprobe/nfs4_file_open")
int netdata_ret_nfs4_file_open(struct pt_regs *ctx)
{
    return netdata_nfs_ret(ctx, NETDATA_KEY_CALLS_OPEN);
}

SEC("kretprobe/nfs_getattr")
int netdata_ret_nfs_getattr(struct pt_regs *ctx)
{
    return netdata_nfs_ret(ctx, NETDATA_KEY_CALLS_SYNC);
}

char _license[] SEC("license") = "GPL";
