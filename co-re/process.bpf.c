#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "netdata_core.h"
#include "netdata_process.h"

/************************************************************************************
 *
 *                                 MAPS
 *
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct netdata_pid_stat_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} tbl_pid_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_GLOBAL_COUNTER);
} tbl_total_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} process_ctrl SEC(".maps");

/************************************************************************************
 *
 *                              COMMON SECTION 
 *
 ***********************************************************************************/

static inline int netdata_common_release_task()
{
    struct netdata_pid_stat_t *fill;
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;

    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_RELEASE_TASK, 1);
    __u32 *apps = bpf_map_lookup_elem(&process_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&key);
    if (fill) {
        libnetdata_update_u32(&fill->release_call, 1) ;
        fill->removeme = 1;
    }

    return 0;
}

static inline int netdata_common_fork_clone(int ret)
{
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    struct netdata_pid_stat_t data = { };
    struct netdata_pid_stat_t *fill;

    if (ret < 0) {
        libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_PROCESS, 1);
    } 

    __u32 *apps = bpf_map_lookup_elem(&process_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&key);
    if (fill) {
        fill->release_call = 0;

        if (ret < 0) {
            libnetdata_update_u32(&fill->task_err, 1) ;
        } 
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  
        if (ret < 0) {
            data.task_err = 1;
        } 
        bpf_map_update_elem(&tbl_pid_stats, &key, &data, BPF_ANY);
    }

    return 0;
}

/************************************************************************************
 *
 *                     PROCESS SECTION (tracepoints)
 *
 ***********************************************************************************/

// It must be always enabled
SEC("tracepoint/sched/sched_process_exit")
int netdata_tracepoint_sched_process_exit(struct netdata_sched_process_exit *ptr)
{
    struct netdata_pid_stat_t *fill;
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;

    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_DO_EXIT, 1);
    __u32 *apps = bpf_map_lookup_elem(&process_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&key);
    if (fill) {
        libnetdata_update_u32(&fill->exit_call, 1) ;
    } 

    return 0;
}

// It must be always enabled
SEC("tracepoint/sched/sched_process_exec")
int netdata_tracepoint_sched_process_exec(struct netdata_sched_process_exec *ptr)
{
    struct netdata_pid_stat_t data = { };
    struct netdata_pid_stat_t *fill;
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    // This is necessary, because it represents the main function to start a thread
    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_PROCESS, 1);

    __u32 *apps = bpf_map_lookup_elem(&process_ctrl, &key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_pid_stats, &key);
    if (fill) {
        fill->release_call = 0;
        libnetdata_update_u32(&fill->create_process, 1) ;
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  
        data.create_process = 1;

        bpf_map_update_elem(&tbl_pid_stats, &key, &data, BPF_ANY);
    }

    return 0;
}

// It must be always enabled
SEC("tracepoint/sched/sched_process_fork")
int netdata_tracepoint_sched_process_fork(struct netdata_sched_process_fork *ptr)
{
    struct netdata_pid_stat_t data = { };
    struct netdata_pid_stat_t *fill;
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;

    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_PROCESS, 1);

    // Parent ID = 1 means that init called process/thread creation
    int thread = 0;
    if (ptr->parent_pid != ptr->child_pid && ptr->parent_pid != 1) {
        thread = 1;
        libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_THREAD, 1);
    }

    __u32 *apps = bpf_map_lookup_elem(&process_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&key);
    if (fill) {
        fill->release_call = 0;
        libnetdata_update_u32(&fill->create_process, 1);
        if (thread)
            libnetdata_update_u32(&fill->create_thread, 1);
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  
        data.create_process = 1;
        if (thread)
            data.create_thread = 1;

        bpf_map_update_elem(&tbl_pid_stats, &key, &data, BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone")
int netdata_clone_exit(struct trace_event_raw_sys_exit *ctx)
{
    int ret = (int)ctx->ret;
    return netdata_common_fork_clone(ret);
}

SEC("tracepoint/syscalls/sys_exit_clone3")
int netdata_clone3_exit(struct trace_event_raw_sys_exit *ctx)
{
    int ret = (int)ctx->ret;
    return netdata_common_fork_clone(ret);
}

SEC("tracepoint/syscalls/sys_exit_fork")
int netdata_fork_exit(struct trace_event_raw_sys_exit *ctx)
{
    int ret = (int)ctx->ret;
    return netdata_common_fork_clone(ret);
}

SEC("tracepoint/syscalls/sys_exit_vfork")
int netdata_vfork_exit(struct trace_event_raw_sys_exit *ctx)
{
    int ret = (int)ctx->ret;
    return netdata_common_fork_clone(ret);
}

/************************************************************************************
 *
 *                     PROCESS SECTION (kprobe)
 *
 ***********************************************************************************/

SEC("kprobe/release_task")
int BPF_KPROBE(netdata_release_task_probe)
{
    return netdata_common_release_task();
}

// Must be disabled on user ring when kernel is newer than 5.9.16
SEC("kretprobe/_do_fork")
int BPF_KPROBE(netdata_do_fork_probe)
{
    int ret = (int)PT_REGS_RC(ctx);
    return netdata_common_fork_clone(ret);
}

// Must be disabled on user ring when kernel is older than 5.10.0
SEC("kretprobe/kernel_clone")
int BPF_KPROBE(netdata_kernel_clone_probe)
{
    int ret = (int)PT_REGS_RC(ctx);
    return netdata_common_fork_clone(ret);
}

/************************************************************************************
 *
 *                     PROCESS SECTION (trampoline)
 *
 ***********************************************************************************/

SEC("fentry/release_task")
int BPF_PROG(netdata_release_task_fentry)
{
    return netdata_common_release_task();
}

SEC("fexit/netdata_clone_fexit")
int BPF_PROG(netdata_clone_fexit, const struct pt_regs *regs)
{
    int ret = (int)PT_REGS_RC(regs);

    return netdata_common_fork_clone(ret);
}

SEC("fexit/netdata_clone3_fexit")
int BPF_PROG(netdata_clone3_fexit, const struct pt_regs *regs)
{
    int ret = (int)PT_REGS_RC(regs);

    return netdata_common_fork_clone(ret);
}

char _license[] SEC("license") = "GPL";

