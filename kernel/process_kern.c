#define KBUILD_MODNAME "process_kern"
#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <linux/threads.h>
#include <linux/sched.h>
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,10,17))
# include <linux/sched/task.h>
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
 *                                 MAPS Section
 *     
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,4,14))
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

#else

struct bpf_map_def SEC("maps") tbl_pid_stats = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct netdata_pid_stat_t),
    .max_entries = PID_MAX_DEFAULT
};

struct bpf_map_def SEC("maps") tbl_total_stats = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries =  NETDATA_GLOBAL_COUNTER
};

struct bpf_map_def SEC("maps") process_ctrl = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = NETDATA_CONTROLLER_END
};

#endif

/************************************************************************************
 *     
 *                                   PROCESS Section
 *     
 ***********************************************************************************/

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

SEC("kprobe/release_task")
int netdata_release_task(struct pt_regs* ctx)
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

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(5,9,16))

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)) 
# if NETDATASEL < 2
SEC("kretprobe/_do_fork")
# else
SEC("kprobe/_do_fork")
# endif
#else 
# if NETDATASEL < 2
SEC("kretprobe/do_fork")
# else
SEC("kprobe/do_fork")
# endif
#endif
int netdata_fork(struct pt_regs* ctx)
{
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    struct netdata_pid_stat_t data = { };
    struct netdata_pid_stat_t *fill;

#if NETDATASEL < 2
    if (ret < 0) {
        libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_PROCESS, 1);
    } 
#endif

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

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_u32(&fill->task_err, 1) ;
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  
#if NETDATASEL < 2
        if (ret < 0) {
            data.task_err = 1;
        } 
#endif
        bpf_map_update_elem(&tbl_pid_stats, &key, &data, BPF_ANY);
    }

    return 0;
}

#else // End kernel <= 5.9.16

#if NETDATASEL < 2
// https://lore.kernel.org/patchwork/patch/1290639/
SEC("kretprobe/kernel_clone")
#else
SEC("kprobe/kernel_clone")
#endif
int netdata_sys_clone(struct pt_regs *ctx)
{
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    struct netdata_pid_stat_t data = { };
    struct netdata_pid_stat_t *fill;
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;

#if NETDATASEL < 2
    if (ret < 0) {
        libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_PROCESS, 1);
    } 
#endif

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

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_u32(&fill->task_err, 1) ;
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;
        data.pid = tgid;

#if NETDATASEL < 2
        if (ret < 0) {
            data.task_err = 1;
        }
#endif

        bpf_map_update_elem(&tbl_pid_stats, &key, &data, BPF_ANY);
    }
    return 0;
}

#endif

char _license[] SEC("license") = "GPL";

