#define KBUILD_MODNAME "latency_pk"
#include <linux/bpf.h>
#include <linux/ptrace.h>

#include "bpf_helpers.h"
#include "netdata_ebpf.h"

typedef struct netdata_latency
{
    __u64 period;
    __u64 counter;
}netdata_latency_t;

struct bpf_map_def SEC("maps") tbl_total_stats = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(netdata_latency_t),
    .max_entries =  NETDATA_GLOBAL_COUNTER
};

struct bpf_map_def SEC("maps") tmp_total_stats = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u64),
    .max_entries =  65536
};


/************************************************************************************
 *     
 *                                 COMMON SECTION
 *     
 ***********************************************************************************/

static unsigned int log2(unsigned int v)
{
    unsigned int r;
    unsigned int shift;

    r = (v > 0xFFFF) << 4; v >>= r;
    shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
    shift = (v > 0xF) << 2; v >>= shift; r |= shift;
    shift = (v > 0x3) << 1; v >>= shift; r |= shift;
    r |= (v >> 1);

    return r;
}

static unsigned int log2l(unsigned long v)
{
    unsigned int hi = v >> 32;
    if (hi)
        return log2(hi) + 32;
    else
        return log2(v);
}

/************************************************************************************
 *     
 *                                 END COMMON SECTION
 *     
 ***********************************************************************************/


SEC("kprobe/vfs_write")
int netdata_enter_vfs_write(struct pt_regs* ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&tmp_total_stats, &pid_tgid, &ts, BPF_ANY);

    return 0;
}

SEC("kretprobe/vfs_write")
int netdata_return_vfs_write(struct pt_regs* ctx)
{
    u64 ts = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *fill;
    netdata_latency_t *nl, data;

    fill = bpf_map_lookup_elem(&tmp_total_stats ,&pid_tgid);
    if (!fill) {
        return 0;
    }

    bpf_map_delete_elem(&tmp_total_stats, &pid_tgid);

    __u32 id = 0;
    pid_tgid = (ts - *fill);
    nl = bpf_map_lookup_elem(&tbl_total_stats ,&id);
    if (nl) {
        nl->period += pid_tgid; 
        nl->counter++;
    } else {
        data.period = pid_tgid;
        data.counter = 1;
        bpf_map_update_elem(&tbl_total_stats, &id, &data, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/vfs_writev")
int netdata_enter_vfs_writev(struct pt_regs* ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&tmp_total_stats, &pid_tgid, &ts, BPF_ANY);

    return 0;
}

SEC("kretprobe/vfs_writev")
int netdata_return_vfs_writev(struct pt_regs* ctx)
{
    u64 ts = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *fill;
    netdata_latency_t *nl, data;

    fill = bpf_map_lookup_elem(&tmp_total_stats ,&pid_tgid);
    if (!fill) {
        return 0;
    }

    bpf_map_delete_elem(&tmp_total_stats, &pid_tgid);

    __u32 id = 1;
    pid_tgid = (ts - *fill);
    nl = bpf_map_lookup_elem(&tbl_total_stats ,&id);
    if (nl) {
        nl->period += pid_tgid; 
        nl->counter++;
    } else {
        data.period = pid_tgid;
        data.counter = 1;
        bpf_map_update_elem(&tbl_total_stats, &id, &data, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/vfs_read")
int netdata_enter_vfs_read(struct pt_regs* ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&tmp_total_stats, &pid_tgid, &ts, BPF_ANY);

    return 0;
}

SEC("kretprobe/vfs_read")
int netdata_return_vfs_read(struct pt_regs* ctx)
{
    u64 ts = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *fill;
    netdata_latency_t *nl, data;

    fill = bpf_map_lookup_elem(&tmp_total_stats ,&pid_tgid);
    if (!fill) {
        return 0;
    }

    bpf_map_delete_elem(&tmp_total_stats, &pid_tgid);

    __u32 id = 2;
    pid_tgid = (ts - *fill);
    nl = bpf_map_lookup_elem(&tbl_total_stats ,&id);
    if (nl) {
        nl->period += pid_tgid; 
        nl->counter++;
    } else {
        data.period = pid_tgid;
        data.counter = 1;
        bpf_map_update_elem(&tbl_total_stats, &id, &data, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/vfs_readv")
int netdata_enter_vfs_readv(struct pt_regs* ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&tmp_total_stats, &pid_tgid, &ts, BPF_ANY);

    return 0;
}

SEC("kretprobe/vfs_readv")
int netdata_return_vfs_readv(struct pt_regs* ctx)
{
    u64 ts = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *fill;
    netdata_latency_t *nl, data;

    fill = bpf_map_lookup_elem(&tmp_total_stats ,&pid_tgid);
    if (!fill) {
        return 0;
    }

    bpf_map_delete_elem(&tmp_total_stats, &pid_tgid);

    __u32 id = 3;
    pid_tgid = (ts - *fill);
    nl = bpf_map_lookup_elem(&tbl_total_stats ,&id);
    if (nl) {
        nl->period += pid_tgid; 
        nl->counter++;
    } else {
        data.period = pid_tgid;
        data.counter = 1;
        bpf_map_update_elem(&tbl_total_stats, &id, &data, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/do_sys_open")
int netdata_enter_do_sys_open(struct pt_regs* ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&tmp_total_stats, &pid_tgid, &ts, BPF_ANY);

    return 0;
}

SEC("kretprobe/do_sys_open")
int netdata_return_do_sys_open(struct pt_regs* ctx)
{
    u64 ts = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *fill;
    netdata_latency_t *nl, data;

    fill = bpf_map_lookup_elem(&tmp_total_stats ,&pid_tgid);
    if (!fill) {
        return 0;
    }

    bpf_map_delete_elem(&tmp_total_stats, &pid_tgid);

    __u32 id = 4;
    pid_tgid = (ts - *fill);
    nl = bpf_map_lookup_elem(&tbl_total_stats ,&id);
    if (nl) {
        nl->period += pid_tgid; 
        nl->counter++;
    } else {
        data.period = pid_tgid;
        data.counter = 1;
        bpf_map_update_elem(&tbl_total_stats, &id, &data, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/vfs_unlink")
int netdata_enter_vfs_unlink(struct pt_regs* ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&tmp_total_stats, &pid_tgid, &ts, BPF_ANY);

    return 0;
}

SEC("kretprobe/vfs_unlink")
int netdata_return_vfs_unlink(struct pt_regs* ctx)
{
    u64 ts = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *fill;
    netdata_latency_t *nl, data;

    fill = bpf_map_lookup_elem(&tmp_total_stats ,&pid_tgid);
    if (!fill) {
        return 0;
    }

    bpf_map_delete_elem(&tmp_total_stats, &pid_tgid);

    __u32 id = 5;
    pid_tgid = (ts - *fill);
    nl = bpf_map_lookup_elem(&tbl_total_stats ,&id);
    if (nl) {
        nl->period += pid_tgid; 
        nl->counter++;
    } else {
        data.period = pid_tgid;
        data.counter = 1;
        bpf_map_update_elem(&tbl_total_stats, &id, &data, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/_do_fork")
int netdata_enter__do_fork(struct pt_regs* ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&tmp_total_stats, &pid_tgid, &ts, BPF_ANY);

    return 0;
}

SEC("kretprobe/_do_fork")
int netdata_return__do_fork(struct pt_regs* ctx)
{
    u64 ts = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *fill;
    netdata_latency_t *nl, data;

    fill = bpf_map_lookup_elem(&tmp_total_stats ,&pid_tgid);
    if (!fill) {
        return 0;
    }

    bpf_map_delete_elem(&tmp_total_stats, &pid_tgid);

    __u32 id = 6;
    pid_tgid = (ts - *fill);
    nl = bpf_map_lookup_elem(&tbl_total_stats ,&id);
    if (nl) {
        nl->period += pid_tgid; 
        nl->counter++;
    } else {
        data.period = pid_tgid;
        data.counter = 1;
        bpf_map_update_elem(&tbl_total_stats, &id, &data, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/__close_fd")
int netdata_enter___close_fd(struct pt_regs* ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&tmp_total_stats, &pid_tgid, &ts, BPF_ANY);

    return 0;
}

SEC("kretprobe/__close_fd")
int netdata_return___close_fd(struct pt_regs* ctx)
{
    u64 ts = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *fill;
    netdata_latency_t *nl, data;

    fill = bpf_map_lookup_elem(&tmp_total_stats ,&pid_tgid);
    if (!fill) {
        return 0;
    }

    bpf_map_delete_elem(&tmp_total_stats, &pid_tgid);

    __u32 id = 7;
    pid_tgid = (ts - *fill);
    nl = bpf_map_lookup_elem(&tbl_total_stats ,&id);
    if (nl) {
        nl->period += pid_tgid; 
        nl->counter++;
    } else {
        data.period = pid_tgid;
        data.counter = 1;
        bpf_map_update_elem(&tbl_total_stats, &id, &data, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
