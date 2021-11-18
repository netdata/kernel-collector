#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"

#include "netdata_core.h"
#include "netdata_fs.h"

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
} tbl_fs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries,  4192);
} tmp_fs SEC(".maps");


/************************************************************************************
 *     
 *                                 COMMON
 *     
 ***********************************************************************************/

static int netdata_fs_entry()
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&tmp_fs, &pid, &ts, BPF_ANY);

    return 0;
}

static int netdata_fs_store_bin(__u32 selection)
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_fs, &pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_fs, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libnetdata_select_idx(data, NETDATA_FS_MAX_BINS_POS);
    __u32 idx = selection * NETDATA_FS_MAX_BINS + bin;
    if (idx >= NETDATA_FS_MAX_ELEMENTS)
        return 0;

    fill = bpf_map_lookup_elem(&tbl_fs, &idx);
    if (fill) {
        libnetdata_update_u64(fill, 1);
		return 0;
    } 

    data = 1;
    bpf_map_update_elem(&tbl_fs, &idx, &data, BPF_ANY);

    return 0;
}

/************************************************************************************
 *     
 *                                 ENTRY SECTION (trampoline)
 *     
 ***********************************************************************************/

SEC("fentry/fs_file_read")
int BPF_PROG(netdata_fs_file_read_entry, struct kiocb *iocb) 
{
    struct file *fp = iocb->ki_filp;
    if (!fp)
        return 0;

    return netdata_fs_entry();
}

SEC("fentry/fs_file_write")
int BPF_PROG(netdata_fs_file_write_entry, struct kiocb *iocb) 
{
    struct file *fp = iocb->ki_filp;
    if (!fp)
        return 0;

    return netdata_fs_entry();
}

SEC("fentry/fs_file_open")
int BPF_PROG(netdata_fs_file_open_entry, struct inode *inode, struct file *filp) 
{
    if (!filp)
        return 0;

    return netdata_fs_entry();
}

SEC("fentry/fs_2nd_file_open")
int BPF_PROG(netdata_fs_2nd_file_open_entry, struct inode *inode, struct file *filp) 
{
    if (!filp)
        return 0;

    return netdata_fs_entry();
}

SEC("fentry/fs_getattr")
int BPF_PROG(netdata_fs_getattr_entry) 
{
    return netdata_fs_entry();
}

/************************************************************************************
 *     
 *                                 END SECTION (trampoline)
 *     
 ***********************************************************************************/

SEC("fexit/fs_file_read")
int BPF_PROG(netdata_fs_file_read_exit)
{
    return netdata_fs_store_bin(NETDATA_KEY_CALLS_READ);
}

SEC("fexit/fs_file_write")
int BPF_PROG(netdata_fs_file_write_exit)
{
    return netdata_fs_store_bin(NETDATA_KEY_CALLS_WRITE);
}

SEC("fexit/fs_file_open")
int BPF_PROG(netdata_fs_file_open_exit)
{
    return netdata_fs_store_bin(NETDATA_KEY_CALLS_OPEN);
}

SEC("fexit/fs_2nd_file_open")
int BPF_PROG(netdata_fs_2nd_file_open_exit)
{
    return netdata_fs_store_bin(NETDATA_KEY_CALLS_OPEN);
}

SEC("fexit/fs_getattr")
int BPF_PROG(netdata_fs_getattr_exit)
{
    return netdata_fs_store_bin(NETDATA_KEY_CALLS_SYNC);
}

/************************************************************************************
 *     
 *                                 ENTRY SECTION (kprobe)
 *     
 ***********************************************************************************/

SEC("kprobe/fs_file_read")
int BPF_KPROBE(netdata_fs_file_read_probe, struct kiocb *iocb) 
{
    struct file *fp = BPF_CORE_READ(iocb, ki_filp);
    if (!fp)
        return 0;

    return netdata_fs_entry();
}

SEC("kprobe/fs_file_write")
int BPF_KPROBE(netdata_fs_file_write_probe, struct kiocb *iocb) 
{
    struct file *fp = BPF_CORE_READ(iocb, ki_filp);
    if (!fp)
        return 0;

    return netdata_fs_entry();
}

SEC("kprobe/fs_file_open")
int BPF_KPROBE(netdata_fs_file_open_probe, struct inode *inode, struct file *filp) 
{
    if (!filp)
        return 0;

    return netdata_fs_entry();
}

SEC("kprobe/fs_2nd_file_open")
int BPF_KPROBE(netdata_fs_2nd_file_open_probe, struct inode *inode, struct file *filp) 
{
    if (!filp)
        return 0;

    return netdata_fs_entry();
}

SEC("kprobe/fs_getattr")
int BPF_KPROBE(netdata_fs_getattr_probe) 
{
    return netdata_fs_entry();
}

/************************************************************************************
 *     
 *                                 END SECTION (kretprobe)
 *     
 ***********************************************************************************/

SEC("kretprobe/fs_file_read")
int BPF_KRETPROBE(netdata_fs_file_read_retprobe)
{
    return netdata_fs_store_bin(NETDATA_KEY_CALLS_READ);
}

SEC("kretprobe/fs_file_write")
int BPF_KRETPROBE(netdata_fs_file_write_retprobe)
{
    return netdata_fs_store_bin(NETDATA_KEY_CALLS_WRITE);
}

SEC("kretprobe/fs_file_open")
int BPF_KRETPROBE(netdata_fs_file_open_retprobe)
{
    return netdata_fs_store_bin(NETDATA_KEY_CALLS_OPEN);
}

SEC("kretprobe/fs_2nd_file_open")
int BPF_KRETPROBE(netdata_fs_2nd_file_open_retprobe)
{
    return netdata_fs_store_bin(NETDATA_KEY_CALLS_OPEN);
}

SEC("kretprobe/fs_getattr")
int BPF_KRETPROBE(netdata_fs_getattr_retprobe)
{
    return netdata_fs_store_bin(NETDATA_KEY_CALLS_SYNC);
}

char _license[] SEC("license") = "GPL";


