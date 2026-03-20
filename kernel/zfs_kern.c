#define KBUILD_MODNAME "zfs_netdata"
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

NETDATA_BPF_PERCPU_ARRAY_DEF(tbl_zfs, __u32, __u64, NETDATA_FS_MAX_ELEMENTS);
NETDATA_BPF_HASH_DEF(tmp_zfs, __u32, __u64, 4192);
NETDATA_BPF_ARRAY_DEF(zfs_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

/************************************************************************************
 *
 *                                 Helper Functions
 *
 ***********************************************************************************/

static __always_inline void netdata_zfs_store_bin(__u32 bin, __u32 selection)
{
    __u32 idx = selection * NETDATA_FS_MAX_BINS + bin;
    if (idx >= NETDATA_FS_MAX_ELEMENTS)
        return;

    __u64 *fill = bpf_map_lookup_elem(&tbl_zfs, &idx);
    if (fill) {
        libnetdata_update_u64(fill, 1);
        return;
    }

    bpf_map_update_elem(&tbl_zfs, &idx, &(unsigned long long){1}, BPF_ANY);
    libnetdata_update_global(&zfs_ctrl, NETDATA_CONTROLLER_TEMP_TABLE_DEL, 1);
}

static __always_inline int netdata_zfs_ret(struct pt_regs *ctx, __u32 selector)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    __u64 *fill = bpf_map_lookup_elem(&tmp_zfs, &tid);
    if (!fill)
        return 0;

    __u64 data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_zfs, &tid);

    if ((s64)data < 0)
        return 0;

    data /= 1000;
    __u32 bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    netdata_zfs_store_bin(bin, selector);

    return 0;
}

/************************************************************************************
 *
 *                                 ENTRY Section
 *
 ***********************************************************************************/

static __always_inline void netdata_zfs_start(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tmp_zfs, &tid, &(__u64){bpf_ktime_get_ns()}, BPF_ANY);
    libnetdata_update_global(&zfs_ctrl, NETDATA_CONTROLLER_TEMP_TABLE_ADD, 1);
}

SEC("kprobe/zpl_iter_read")
int netdata_zpl_iter_read(struct pt_regs *ctx)
{
    netdata_zfs_start(ctx);
    return 0;
}

SEC("kprobe/zpl_iter_write")
int netdata_zpl_iter_write(struct pt_regs *ctx)
{
    netdata_zfs_start(ctx);
    return 0;
}

SEC("kprobe/zpl_open")
int netdata_zpl_open(struct pt_regs *ctx)
{
    netdata_zfs_start(ctx);
    return 0;
}

SEC("kprobe/zpl_fsync")
int netdata_zpl_fsync(struct pt_regs *ctx)
{
    netdata_zfs_start(ctx);
    return 0;
}

/************************************************************************************
 *
 *                                 END Section
 *
 ***********************************************************************************/

SEC("kretprobe/zpl_iter_read")
int netdata_ret_zpl_iter_read(struct pt_regs *ctx)
{
    return netdata_zfs_ret(ctx, NETDATA_KEY_CALLS_READ);
}

SEC("kretprobe/zpl_iter_write")
int netdata_ret_zpl_iter_write(struct pt_regs *ctx)
{
    return netdata_zfs_ret(ctx, NETDATA_KEY_CALLS_WRITE);
}

SEC("kretprobe/zpl_open")
int netdata_ret_zpl_open(struct pt_regs *ctx)
{
    return netdata_zfs_ret(ctx, NETDATA_KEY_CALLS_OPEN);
}

SEC("kretprobe/zpl_fsync")
int netdata_ret_zpl_fsync(struct pt_regs *ctx)
{
    return netdata_zfs_ret(ctx, NETDATA_KEY_CALLS_SYNC);
}

char _license[] SEC("license") = "GPL";
