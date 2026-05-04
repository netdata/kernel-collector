#define KBUILD_MODNAME "process_buffer_kern"
#include <linux/version.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,10,17))
# include <linux/sched/task.h>
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "netdata_common.h"
#include "netdata_arena_common.h"
#include "netdata_process.h"
#include "netdata_process_buffer.h"

/************************************************************************************
 *
 *                                 MAPS Section
 *
 ***********************************************************************************/

NETDATA_BPF_RINGBUF_DEF(process_events, NETDATA_PROCESS_RINGBUF_SIZE);
NETDATA_BPF_PERCPU_ARRAY_DEF(tbl_total_stats, __u32, __u64, NETDATA_GLOBAL_COUNTER);
NETDATA_BPF_ARRAY_DEF(process_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

/************************************************************************************
 *
 *                                Local Functions
 *
 ***********************************************************************************/

static __always_inline void netdata_process_fill_event(struct netdata_process_event_t __arena *ev, void *ctrl)
{
    __u32 tgid = 0;
    char comm[TASK_COMM_LEN];
    ev->ct   = bpf_ktime_get_ns();
    ev->pid  = netdata_get_pid(ctrl, &tgid);
    ev->tgid = tgid;
    {
        __u64 uid_gid = bpf_get_current_uid_gid();
        ev->uid = (__u32)uid_gid;
        ev->gid = (__u32)(uid_gid >> 32);
    }
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
    bpf_get_current_comm(comm, TASK_COMM_LEN);
#pragma unroll
    for (int i = 0; i < TASK_COMM_LEN; i++)
        ev->name[i] = comm[i];
#else
    ev->name[0] = '\0';
#endif
    ev->pad[0] = ev->pad[1] = ev->pad[2] = 0;
}

/************************************************************************************
 *
 *                                   Probes Section
 *
 ***********************************************************************************/

SEC("tracepoint/sched/sched_process_exit")
int netdata_tracepoint_sched_process_exit_buffer(struct netdata_sched_process_exit *ptr)
{
    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_DO_EXIT, 1);

    if (!monitor_apps(&process_ctrl))
        return 0;

    struct netdata_process_event_t __arena *ev = bpf_ringbuf_reserve(&process_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_process_fill_event(ev, &process_ctrl);
    ev->action = NETDATA_PROCESS_EVENT_EXIT;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kprobe/release_task")
int netdata_release_task_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_RELEASE_TASK, 1);

    if (!monitor_apps(&process_ctrl))
        return 0;

    struct netdata_process_event_t __arena *ev = bpf_ringbuf_reserve(&process_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_process_fill_event(ev, &process_ctrl);
    ev->action = NETDATA_PROCESS_EVENT_RELEASE;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int netdata_tracepoint_sched_process_exec_buffer(struct netdata_sched_process_exec *ptr)
{
    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_PROCESS, 1);

    if (!monitor_apps(&process_ctrl))
        return 0;

    struct netdata_process_event_t __arena *ev = bpf_ringbuf_reserve(&process_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_process_fill_event(ev, &process_ctrl);
    ev->action = NETDATA_PROCESS_EVENT_EXEC;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int netdata_tracepoint_sched_process_fork_buffer(void *ctx)
{
    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_PROCESS, 1);

    /*
     * Read parent_pid and child_pid via byte offsets to avoid direct typed-context
     * dereference, which can interfere with user-ring metadata consumers on newer kernels.
     * Offsets come from /sys/kernel/tracing/events/sched/sched_process_fork/format.
     */
    int parent_pid = 0, child_pid = 0;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,16,0))
    /* fork_v2: u64 pad(0) + char[4](8) + int parent_pid(12) + char[4](16) + int child_pid(20) */
    bpf_probe_read(&parent_pid, sizeof(parent_pid), (char *)ctx + 12);
    bpf_probe_read(&child_pid,  sizeof(child_pid),  (char *)ctx + 20);
#else
    /* fork_v1: u64 pad(0) + char[16](8) + int parent_pid(24) + char[16](28) + int child_pid(44) */
    bpf_probe_read(&parent_pid, sizeof(parent_pid), (char *)ctx + 24);
    bpf_probe_read(&child_pid,  sizeof(child_pid),  (char *)ctx + 44);
#endif

    __u8 is_thread = (parent_pid != child_pid && parent_pid != 1) ? 1 : 0;
    if (is_thread)
        libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_THREAD, 1);

    if (!monitor_apps(&process_ctrl))
        return 0;

    struct netdata_process_event_t __arena *ev = bpf_ringbuf_reserve(&process_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_process_fill_event(ev, &process_ctrl);
    ev->action = is_thread ? NETDATA_PROCESS_EVENT_THREAD : NETDATA_PROCESS_EVENT_FORK;

    bpf_ringbuf_submit(ev, 0);
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
int netdata_fork_buffer(struct pt_regs *ctx)
{
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0) {
        libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_PROCESS, 1);

        if (monitor_apps(&process_ctrl)) {
            struct netdata_process_event_t __arena *ev = bpf_ringbuf_reserve(&process_events, sizeof(*ev), 0);
            if (ev) {
                netdata_process_fill_event(ev, &process_ctrl);
                ev->action = NETDATA_PROCESS_EVENT_FORK_ERR;
                bpf_ringbuf_submit(ev, 0);
            }
        }
    }
#endif
    return 0;
}

#else

#if NETDATASEL < 2
SEC("kretprobe/kernel_clone")
#else
SEC("kprobe/kernel_clone")
#endif
int netdata_sys_clone_buffer(struct pt_regs *ctx)
{
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0) {
        libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_PROCESS, 1);

        if (monitor_apps(&process_ctrl)) {
            struct netdata_process_event_t __arena *ev = bpf_ringbuf_reserve(&process_events, sizeof(*ev), 0);
            if (ev) {
                netdata_process_fill_event(ev, &process_ctrl);
                ev->action = NETDATA_PROCESS_EVENT_FORK_ERR;
                bpf_ringbuf_submit(ev, 0);
            }
        }
    }
#endif
    return 0;
}

#endif

char _license[] SEC("license") = "GPL";
