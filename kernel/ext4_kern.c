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
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(netdata_fs_hist_t),
    .value_size = sizeof(__u64),
    .max_entries = 8192
};

struct bpf_map_def SEC("maps") tmp_ext4 = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 8192
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

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,0,0))
static int netdata_ext4_end(struct pt_regs *ctx, __u32 selection)
#elif (LINUX_VERSION_CODE > KERNEL_VERSION(4,19,0)) 
static __always_inline int netdata_ext4_end(struct pt_regs *ctx, __u32 selection)
#else
static inline int netdata_ext4_end(struct pt_regs *ctx, __u32 selection)
#endif
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    netdata_fs_hist_t blk;

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

    blk.hist_id = selection;
    blk.bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);

    fill = bpf_map_lookup_elem(&tbl_ext4 ,&blk);
    if (fill) {
        libnetdata_update_u64(fill, 1);
    } else {
        data = 1;
        bpf_map_update_elem(&tbl_ext4, &blk, &data, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/ext4_file_read_iter")
int netdata_ret_ext4_ext4_file_read_iter(struct pt_regs *ctx)
{
    return netdata_ext4_end(ctx, NETDATA_KEY_CALLS_READ);
}

SEC("kretprobe/ext4_file_write_iter")
int netdata_ret_ext4_file_write_iter(struct pt_regs *ctx)
{
    return netdata_ext4_end(ctx, NETDATA_KEY_CALLS_WRITE);
}

SEC("kretprobe/ext4_file_open")
int netdata_ret_ext4_file_open(struct pt_regs *ctx)
{
    return netdata_ext4_end(ctx, NETDATA_KEY_CALLS_OPEN);
}

SEC("kretprobe/ext4_sync_file")
int netdata_ret_ext4_sync_file(struct pt_regs *ctx) 
{
    return netdata_ext4_end(ctx, NETDATA_KEY_CALLS_SYNC);
}

char _license[] SEC("license") = "GPL";

