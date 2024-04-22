#define KBUILD_MODNAME "xfs_netdata"
#include <linux/ptrace.h>
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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_FS_MAX_ELEMENTS);
} tbl_xfs SEC(".maps");

struct {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    __uint(type, BPF_MAP_TYPE_HASH);
#else
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#endif
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries,  4192);
} tmp_xfs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} xfs_ctrl SEC(".maps");

/************************************************************************************
 *     
 *                                 ENTRY Section
 *     
 ***********************************************************************************/

static __always_inline int netdata_xfs_entry()
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&tmp_xfs, &pid, &ts, BPF_ANY);

    libnetdata_update_global(&xfs_ctrl, NETDATA_CONTROLLER_TEMP_TABLE_ADD, 1);

    return 0;
}

SEC("kprobe/xfs_file_read_iter")
int netdata_xfs_file_read_iter(struct pt_regs *ctx) 
{
    return netdata_xfs_entry();
}

SEC("kprobe/xfs_file_write_iter")
int netdata_xfs_file_write_iter(struct pt_regs *ctx) 
{
    return netdata_xfs_entry();
}

SEC("kprobe/xfs_file_open")
int netdata_xfs_file_open(struct pt_regs *ctx) 
{
    return netdata_xfs_entry();
}

SEC("kprobe/xfs_file_fsync")
int netdata_xfs_file_fsync(struct pt_regs *ctx) 
{
    return netdata_xfs_entry();
}

/************************************************************************************
 *     
 *                                 END Section
 *     
 ***********************************************************************************/

static void netdata_xfs_store_bin(__u32 bin, __u32 selection)
{
    __u64 *fill, data;
    __u32 idx = selection * NETDATA_FS_MAX_BINS + bin;
    if (idx >= NETDATA_FS_MAX_ELEMENTS)
        return;

    fill = bpf_map_lookup_elem(&tbl_xfs, &idx);
    if (fill) {
        libnetdata_update_u64(fill, 1);
		return;
    } 

    data = 1;
    bpf_map_update_elem(&tbl_xfs, &idx, &data, BPF_ANY);

    libnetdata_update_global(&xfs_ctrl, NETDATA_CONTROLLER_TEMP_TABLE_DEL, 1);
}

SEC("kretprobe/xfs_file_read_iter")
int netdata_ret_xfs_file_read_iter(struct pt_regs *ctx)
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_xfs, &pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_xfs, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    netdata_xfs_store_bin(bin, NETDATA_KEY_CALLS_READ);

    return 0;
}

SEC("kretprobe/xfs_file_write_iter")
int netdata_ret_xfs_file_write_iter(struct pt_regs *ctx)
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_xfs, &pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_xfs, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    netdata_xfs_store_bin(bin, NETDATA_KEY_CALLS_WRITE);

    return 0;
}

SEC("kretprobe/xfs_file_open")
int netdata_ret_xfs_file_open(struct pt_regs *ctx)
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_xfs, &pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_xfs, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    netdata_xfs_store_bin(bin, NETDATA_KEY_CALLS_OPEN);

    return 0;
}

SEC("kretprobe/xfs_file_fsync")
int netdata_ret_xfs_file_fsync(struct pt_regs *ctx) 
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_xfs, &pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_xfs, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    netdata_xfs_store_bin(bin, NETDATA_KEY_CALLS_SYNC);

    return 0;
}

char _license[] SEC("license") = "GPL";

