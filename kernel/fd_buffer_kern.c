#define KBUILD_MODNAME "fd_buffer_kern"
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
#include "netdata_fd.h"
#include "netdata_fd_buffer.h"

/************************************************************************************
 *
 *                                 MAPS Section
 *
 ***********************************************************************************/

NETDATA_BPF_RINGBUF_DEF(fd_events, NETDATA_FD_RINGBUF_SIZE);
NETDATA_BPF_PERCPU_ARRAY_DEF(tbl_fd_global, __u32, __u64, NETDATA_FD_COUNTER);
NETDATA_BPF_ARRAY_DEF(fd_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

/************************************************************************************
 *
 *                                Local Functions
 *
 ***********************************************************************************/

static __always_inline void netdata_fd_fill_event(struct netdata_fd_event_t *ev, void *ctrl)
{
    __u32 tgid = 0;
    ev->ct   = bpf_ktime_get_ns();
    ev->pid  = netdata_get_pid(ctrl, &tgid);
    ev->tgid = tgid;
    libnetdata_update_uid_gid(&ev->uid, &ev->gid);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
    bpf_get_current_comm(ev->name, TASK_COMM_LEN);
#else
    ev->name[0] = '\0';
#endif
    ev->pad[0] = ev->pad[1] = 0;
}

/************************************************************************************
 *
 *                                   Probes Section
 *
 ***********************************************************************************/

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(5,5,19))
#if NETDATASEL < 2
SEC("kretprobe/do_sys_open")
#else
SEC("kprobe/do_sys_open")
#endif
#else
#if NETDATASEL < 2
SEC("kretprobe/do_sys_openat2")
#else
SEC("kprobe/do_sys_openat2")
#endif
#endif
int netdata_sys_open_buffer(struct pt_regs *ctx)
{
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif

    libnetdata_update_global(&tbl_fd_global, NETDATA_KEY_CALLS_DO_SYS_OPEN, 1);
#if NETDATASEL < 2
    if (ret < 0)
        libnetdata_update_global(&tbl_fd_global, NETDATA_KEY_ERROR_DO_SYS_OPEN, 1);
#endif

    if (!monitor_apps(&fd_ctrl))
        return 0;

    struct netdata_fd_event_t *ev = bpf_ringbuf_reserve(&fd_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_fd_fill_event(ev, &fd_ctrl);
    ev->action = NETDATA_FD_EVENT_OPEN;
#if NETDATASEL < 2
    ev->error  = (ret < 0) ? 1 : 0;
#else
    ev->error  = 0;
#endif

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0))
#if NETDATASEL < 2
SEC("kretprobe/close_fd")
#else
SEC("kprobe/close_fd")
#endif
#elif defined(RHEL_MAJOR) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)) && (LINUX_VERSION_CODE <= KERNEL_VERSION(4,19,0))
#if NETDATASEL < 2
SEC("kretprobe/close_fd")
#else
SEC("kprobe/close_fd")
#endif
#else
#if NETDATASEL < 2
SEC("kretprobe/__close_fd")
#else
SEC("kprobe/__close_fd")
#endif
#endif
int netdata_close_buffer(struct pt_regs *ctx)
{
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif

    libnetdata_update_global(&tbl_fd_global, NETDATA_KEY_CALLS_CLOSE_FD, 1);
#if NETDATASEL < 2
    if (ret < 0)
        libnetdata_update_global(&tbl_fd_global, NETDATA_KEY_ERROR_CLOSE_FD, 1);
#endif

    if (!monitor_apps(&fd_ctrl))
        return 0;

    struct netdata_fd_event_t *ev = bpf_ringbuf_reserve(&fd_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_fd_fill_event(ev, &fd_ctrl);
    ev->action = NETDATA_FD_EVENT_CLOSE;
#if NETDATASEL < 2
    ev->error  = (ret < 0) ? 1 : 0;
#else
    ev->error  = 0;
#endif

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
