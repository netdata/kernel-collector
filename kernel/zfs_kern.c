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

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_FS_MAX_ELEMENTS);
} tbl_zfs SEC(".maps");

struct {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    __uint(type, BPF_MAP_TYPE_HASH);
#else
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#endif
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries,  4192);
} tmp_zfs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} zfs_ctrl SEC(".maps");

#else
struct bpf_map_def SEC("maps") tbl_zfs = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_FS_MAX_ELEMENTS
};

struct bpf_map_def SEC("maps") tmp_zfs = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4192
};

struct bpf_map_def SEC("maps") zfs_ctrl = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_CONTROLLER_END
};
#endif

/************************************************************************************
 *     
 *                                 ENTRY Section
 *     
 ***********************************************************************************/

static __always_inline int netdata_zfs_entry()
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&tmp_zfs, &pid, &ts, BPF_ANY);

    libnetdata_update_global(&zfs_ctrl, NETDATA_CONTROLLER_TEMP_TABLE_ADD, 1);

    return 0;
}

SEC("kprobe/zpl_iter_read")
int netdata_zpl_iter_read(struct pt_regs *ctx) 
{
    return netdata_zfs_entry();
}

SEC("kprobe/zpl_iter_write")
int netdata_zpl_iter_write(struct pt_regs *ctx) 
{
    return netdata_zfs_entry();
}

SEC("kprobe/zpl_open")
int netdata_zpl_open(struct pt_regs *ctx) 
{
    return netdata_zfs_entry();
}

SEC("kprobe/zpl_fsync")
int netdata_zpl_fsync(struct pt_regs *ctx) 
{
    return netdata_zfs_entry();
}

/************************************************************************************
 *     
 *                                 END Section
 *     
 ***********************************************************************************/

static void netdata_zfs_store_bin(__u32 bin, __u32 selection)
{
    __u64 *fill, data;
    __u32 idx = selection * NETDATA_FS_MAX_BINS + bin;
    if (idx >= NETDATA_FS_MAX_ELEMENTS)
        return;

    fill = bpf_map_lookup_elem(&tbl_zfs, &idx);
    if (fill) {
        libnetdata_update_u64(fill, 1);
		return;
    } 

    data = 1;
    bpf_map_update_elem(&tbl_zfs, &idx, &data, BPF_ANY);

    libnetdata_update_global(&zfs_ctrl, NETDATA_CONTROLLER_TEMP_TABLE_DEL, 1);
}

SEC("kretprobe/zpl_iter_read")
int netdata_ret_zpl_iter_read(struct pt_regs *ctx)
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_zfs, &pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_zfs, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    netdata_zfs_store_bin(bin, NETDATA_KEY_CALLS_READ);

    return 0;
}

SEC("kretprobe/zpl_iter_write")
int netdata_ret_zpl_iter_write(struct pt_regs *ctx)
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_zfs, &pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_zfs, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    netdata_zfs_store_bin(bin, NETDATA_KEY_CALLS_WRITE);

    return 0;
}

SEC("kretprobe/zpl_open")
int netdata_ret_zpl_open(struct pt_regs *ctx)
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_zfs, &pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_zfs, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    netdata_zfs_store_bin(bin, NETDATA_KEY_CALLS_OPEN);

    return 0;
}

SEC("kretprobe/zpl_fsync")
int netdata_ret_zpl_fsync(struct pt_regs *ctx) 
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_zfs, &pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_zfs, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    netdata_zfs_store_bin(bin, NETDATA_KEY_CALLS_SYNC);

    return 0;
}

char _license[] SEC("license") = "GPL";

