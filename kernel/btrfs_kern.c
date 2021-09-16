#define KBUILD_MODNAME "btrfs_netdata"
#include <linux/bpf.h>
#include <linux/genhd.h>
#include <linux/version.h>
// Condition added because struct kiocb was moved when 4.1.0 was released
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0))
#include <linux/aio.h>
#else
#include <linux/fs.h>
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,4,14))
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#else
#include "netdata_bpf_helpers.h"
#endif
#include "netdata_ebpf.h"

/************************************************************************************
 *     
 *                                 MAP Section
 *     
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,4,14))
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_FS_MAX_ELEMENTS);
} tbl_btrfs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries,  1);
} tbl_ext_addr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries,  4192);
} tmp_btrfs SEC(".maps");

#else

struct bpf_map_def SEC("maps") tbl_btrfs = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_FS_MAX_ELEMENTS
};

struct bpf_map_def SEC("maps") tbl_ext_addr = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1
};

struct bpf_map_def SEC("maps") tmp_btrfs = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4192
};
#endif

/************************************************************************************
 *     
 *                                 ENTRY Section
 *     
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,0,0))
static int netdata_btrfs_entry()
#elif (LINUX_VERSION_CODE > KERNEL_VERSION(4,19,0)) 
static __always_inline int netdata_btrfs_entry()
#else
static inline int netdata_btrfs_entry()
#endif
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&tmp_btrfs, &pid, &ts, BPF_ANY);

    return 0;
}

// We need different probes here, because struct file_operations (btrfs_file_operations)
// was modified when 5.10 was released.
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0))
SEC("kprobe/btrfs_file_read_iter")
int netdata_btrfs_file_read_iter(struct pt_regs *ctx) 
#else
SEC("kprobe/generic_file_read_iter")
int netdata_generic_file_read_iter(struct pt_regs *ctx) 
#endif
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0))
    __u32 key = 0;
    struct kiocb *ptr = (struct kiocb *)PT_REGS_PARM1(ctx);
    struct file *kf = _(ptr->ki_filp);
    if (kf) {
        struct file_operations *fo = _(kf->f_op);
        if (fo) {
            __u64 *bfo = bpf_map_lookup_elem(&tbl_ext_addr, &key);
            if (bfo) {
                if((__u64)fo != *bfo) {
                    return 0;
                }
            }
        }
    }
#endif

    return netdata_btrfs_entry();
}

SEC("kprobe/btrfs_file_write_iter")
int netdata_btrfs_file_write_iter(struct pt_regs *ctx) 
{
    return netdata_btrfs_entry();
}

SEC("kprobe/btrfs_file_open")
int netdata_btrfs_file_open(struct pt_regs *ctx) 
{
    return netdata_btrfs_entry();
}

SEC("kprobe/btrfs_sync_file")
int netdata_btrfs_sync_file(struct pt_regs *ctx) 
{
    return netdata_btrfs_entry();
}

/************************************************************************************
 *     
 *                                 END Section
 *     
 ***********************************************************************************/

static void netdata_btrfs_store_bin(__u32 bin, __u32 selection)
{
    __u64 *fill, data;
    __u32 idx = selection * NETDATA_FS_MAX_BINS + bin;
    if (idx >= NETDATA_FS_MAX_ELEMENTS)
        return;

    fill = bpf_map_lookup_elem(&tbl_btrfs, &idx);
    if (fill) {
        libnetdata_update_u64(fill, 1);
		return;
    } 

    data = 1;
    bpf_map_update_elem(&tbl_btrfs, &idx, &data, BPF_ANY);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0))
SEC("kretprobe/btrfs_file_read_iter")
int netdata_ret_btrfs_file_read_iter(struct pt_regs *ctx)
#else
SEC("kretprobe/generic_file_read_iter")
int netdata_ret_generic_file_read_iter(struct pt_regs *ctx)
#endif
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_btrfs, &pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_btrfs, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    netdata_btrfs_store_bin(bin, NETDATA_KEY_CALLS_READ);

    return 0;
}

SEC("kretprobe/btrfs_file_write_iter")
int netdata_ret_btrfs_file_write_iter(struct pt_regs *ctx)
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_btrfs, &pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_btrfs, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    netdata_btrfs_store_bin(bin, NETDATA_KEY_CALLS_WRITE);

    return 0;
}

SEC("kretprobe/btrfs_file_open")
int netdata_ret_btrfs_file_open(struct pt_regs *ctx)
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_btrfs, &pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_btrfs, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    netdata_btrfs_store_bin(bin, NETDATA_KEY_CALLS_OPEN);

    return 0;
}

SEC("kretprobe/btrfs_sync_file")
int netdata_ret_btrfs_sync_file(struct pt_regs *ctx) 
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_btrfs, &pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_btrfs, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    netdata_btrfs_store_bin(bin, NETDATA_KEY_CALLS_SYNC);

    return 0;
}

char _license[] SEC("license") = "GPL";

