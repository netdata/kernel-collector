#define KBUILD_MODNAME "ext4_netdata"
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

NETDATA_BPF_PERCPU_ARRAY_DEF(tbl_ext4, __u32, __u64, NETDATA_FS_MAX_ELEMENTS);
NETDATA_BPF_HASH_DEF(tmp_ext4, __u32, __u64, 4192);
NETDATA_BPF_ARRAY_DEF(ext4_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

/************************************************************************************
 *
 *                                 Helper Functions
 *
 ***********************************************************************************/

static __always_inline void netdata_ext4_store_bin(__u32 bin, __u32 selection)
{
    __u32 idx = selection * NETDATA_FS_MAX_BINS + bin;
    if (idx >= NETDATA_FS_MAX_ELEMENTS)
        return;

    __u64 *fill = bpf_map_lookup_elem(&tbl_ext4, &idx);
    if (fill) {
        libnetdata_update_u64(fill, 1);
        return;
    }

    bpf_map_update_elem(&tbl_ext4, &idx, &(unsigned long long){1}, BPF_ANY);
    libnetdata_update_global(&ext4_ctrl, NETDATA_CONTROLLER_TEMP_TABLE_DEL, 1);
}

static __always_inline int netdata_ext4_ret(struct pt_regs *ctx, __u32 selector)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    __u64 *fill = bpf_map_lookup_elem(&tmp_ext4, &tid);
    if (!fill)
        return 0;

    __u64 data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_ext4, &tid);

    if ((s64)data < 0)
        return 0;

    data /= 1000;
    __u32 bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    netdata_ext4_store_bin(bin, selector);

    return 0;
}

/************************************************************************************
 *
 *                                 ENTRY Section
 *
 ***********************************************************************************/

SEC("kprobe/ext4_file_read_iter")
int netdata_ext4_file_read_iter(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tmp_ext4, &tid, &(unsigned long long){bpf_ktime_get_ns()}, BPF_ANY);
    libnetdata_update_global(&ext4_ctrl, NETDATA_CONTROLLER_TEMP_TABLE_ADD, 1);
    return 0;
}

SEC("kprobe/ext4_file_write_iter")
int netdata_ext4_file_write_iter(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tmp_ext4, &tid, &(unsigned long long){bpf_ktime_get_ns()}, BPF_ANY);
    libnetdata_update_global(&ext4_ctrl, NETDATA_CONTROLLER_TEMP_TABLE_ADD, 1);
    return 0;
}

SEC("kprobe/ext4_file_open")
int netdata_ext4_file_open(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tmp_ext4, &tid, &(unsigned long long){bpf_ktime_get_ns()}, BPF_ANY);
    libnetdata_update_global(&ext4_ctrl, NETDATA_CONTROLLER_TEMP_TABLE_ADD, 1);
    return 0;
}

SEC("kprobe/ext4_sync_file")
int netdata_ext4_sync_file(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tmp_ext4, &tid, &(unsigned long long){bpf_ktime_get_ns()}, BPF_ANY);
    libnetdata_update_global(&ext4_ctrl, NETDATA_CONTROLLER_TEMP_TABLE_ADD, 1);
    return 0;
}

/************************************************************************************
 *
 *                                 END Section
 *
 ***********************************************************************************/

SEC("kretprobe/ext4_file_read_iter")
int netdata_ret_ext4_file_read_iter(struct pt_regs *ctx)
{
    return netdata_ext4_ret(ctx, NETDATA_KEY_CALLS_READ);
}

SEC("kretprobe/ext4_file_write_iter")
int netdata_ret_ext4_file_write_iter(struct pt_regs *ctx)
{
    return netdata_ext4_ret(ctx, NETDATA_KEY_CALLS_WRITE);
}

SEC("kretprobe/ext4_file_open")
int netdata_ret_ext4_file_open(struct pt_regs *ctx)
{
    return netdata_ext4_ret(ctx, NETDATA_KEY_CALLS_OPEN);
}

SEC("kretprobe/ext4_sync_file")
int netdata_ret_ext4_sync_file(struct pt_regs *ctx)
{
    return netdata_ext4_ret(ctx, NETDATA_KEY_CALLS_SYNC);
}

char _license[] SEC("license") = "GPL";
