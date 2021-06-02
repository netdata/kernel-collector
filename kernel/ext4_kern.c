#define KBUILD_MODNAME "ext4_netdata"
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/genhd.h>

#include "bpf_helpers.h"
#include "netdata_ebpf.h"

/************************************************************************************
 *     
 *                                 MAP Section
 *     
 ***********************************************************************************/

struct bpf_map_def SEC("maps") tbl_ext4 = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_FS_MAX_ELEMENTS
};

struct bpf_map_def SEC("maps") tmp_ext4 = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4192
};

/************************************************************************************
 *     
 *                                 ENTRY Section
 *     
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,0,0))
static int netdata_ext4_entry(struct pt_regs *ctx)
#elif (LINUX_VERSION_CODE > KERNEL_VERSION(4,19,0)) 
static __always_inline int netdata_ext4_entry(struct pt_regs *ctx)
#else
static inline int netdata_ext4_entry(struct pt_regs *ctx)
#endif
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&tmp_ext4, &pid, &ts, BPF_ANY);

    return 0;
}

SEC("kprobe/ext4_file_read_iter")
int netdata_ext4_file_read_iter(struct pt_regs *ctx) 
{
    return netdata_ext4_entry(ctx);
}

SEC("kprobe/ext4_file_write_iter")
int netdata_ext4_file_write_iter(struct pt_regs *ctx) 
{
    return netdata_ext4_entry(ctx);
}

SEC("kprobe/ext4_file_open")
int netdata_ext4_file_open(struct pt_regs *ctx) 
{
    return netdata_ext4_entry(ctx);
}

SEC("kprobe/ext4_sync_file")
int netdata_ext4_sync_file(struct pt_regs *ctx) 
{
    return netdata_ext4_entry(ctx);
}

/************************************************************************************
 *     
 *                                 END Section
 *     
 ***********************************************************************************/

static void netdata_ext4_store_bin(__u32 bin, __u32 selection)
{
    __u64 *fill, data;
    __u32 idx = selection*NETDATA_FS_MAX_BINS + bin;
    if (idx >= NETDATA_FS_MAX_ELEMENTS)
        return;

    fill = bpf_map_lookup_elem(&tbl_ext4 ,&idx);
    if (fill) {
        libnetdata_update_u64(fill, 1);
		return;
    } 

    data = 1;
    bpf_map_update_elem(&tbl_ext4, &idx, &data, BPF_ANY);
}

SEC("kretprobe/ext4_file_read_iter")
int netdata_ret_ext4_ext4_file_read_iter(struct pt_regs *ctx)
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_ext4 ,&pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_ext4, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    netdata_ext4_store_bin(bin, NETDATA_KEY_CALLS_READ);

	return 0;
}

SEC("kretprobe/ext4_file_write_iter")
int netdata_ret_ext4_file_write_iter(struct pt_regs *ctx)
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_ext4 ,&pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_ext4, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    netdata_ext4_store_bin(bin, NETDATA_KEY_CALLS_WRITE);

	return 0;
}

SEC("kretprobe/ext4_file_open")
int netdata_ret_ext4_file_open(struct pt_regs *ctx)
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_ext4 ,&pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_ext4, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    netdata_ext4_store_bin(bin, NETDATA_KEY_CALLS_OPEN);

	return 0;
}

SEC("kretprobe/ext4_sync_file")
int netdata_ret_ext4_sync_file(struct pt_regs *ctx) 
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_ext4 ,&pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_ext4, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    netdata_ext4_store_bin(bin, NETDATA_KEY_CALLS_SYNC);

	return 0;
}

char _license[] SEC("license") = "GPL";

