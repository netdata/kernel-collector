#define KBUILD_MODNAME "vfs_buffer_kern"
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
#include "netdata_vfs.h"
#include "netdata_vfs_buffer.h"

/************************************************************************************
 *
 *                                 MAPS Section
 *
 ***********************************************************************************/

NETDATA_BPF_RINGBUF_DEF(vfs_events, NETDATA_VFS_RINGBUF_SIZE);
NETDATA_BPF_PERCPU_ARRAY_DEF(tbl_vfs_stats, __u32, __u64, NETDATA_VFS_COUNTER);
NETDATA_BPF_ARRAY_DEF(vfs_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

/************************************************************************************
 *
 *                                Local Functions
 *
 ***********************************************************************************/

static __always_inline void netdata_vfs_fill_event(struct netdata_vfs_event_t __arena *ev, void *ctrl)
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
    ev->pad[0] = ev->pad[1] = 0;
}

/************************************************************************************
 *
 *                                   Probes Section
 *
 ***********************************************************************************/

#if NETDATASEL < 2
SEC("kretprobe/vfs_write")
#else
SEC("kprobe/vfs_write")
#endif
int netdata_sys_write_buffer(struct pt_regs *ctx)
{
    ssize_t bytes = (ssize_t)PT_REGS_PARM3(ctx);
#if NETDATASEL < 2
    __u8 err = ((ssize_t)PT_REGS_RC(ctx) < 0) ? 1 : 0;
#else
    __u8 err = 0;
#endif

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_WRITE, 1);
#if NETDATASEL < 2
    if (err)
        libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_WRITE, 1);
#endif
    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_WRITE, libnetdata_log2l(bytes));

    if (!monitor_apps(&vfs_ctrl))
        return 0;

    struct netdata_vfs_event_t __arena *ev = bpf_ringbuf_reserve(&vfs_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_vfs_fill_event(ev, &vfs_ctrl);
    ev->bytes  = (__u64)bytes;
    ev->action = NETDATA_VFS_EVENT_WRITE;
    ev->error  = err;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_writev")
#else
SEC("kprobe/vfs_writev")
#endif
int netdata_sys_writev_buffer(struct pt_regs *ctx)
{
    ssize_t bytes = (ssize_t)PT_REGS_PARM3(ctx);
#if NETDATASEL < 2
    __u8 err = ((ssize_t)PT_REGS_RC(ctx) < 0) ? 1 : 0;
#else
    __u8 err = 0;
#endif

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_WRITEV, 1);
#if NETDATASEL < 2
    if (err)
        libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_WRITEV, 1);
#endif
    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_WRITEV, libnetdata_log2l(bytes));

    if (!monitor_apps(&vfs_ctrl))
        return 0;

    struct netdata_vfs_event_t __arena *ev = bpf_ringbuf_reserve(&vfs_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_vfs_fill_event(ev, &vfs_ctrl);
    ev->bytes  = (__u64)bytes;
    ev->action = NETDATA_VFS_EVENT_WRITEV;
    ev->error  = err;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_read")
#else
SEC("kprobe/vfs_read")
#endif
int netdata_sys_read_buffer(struct pt_regs *ctx)
{
    ssize_t bytes = (ssize_t)PT_REGS_PARM3(ctx);
#if NETDATASEL < 2
    __u8 err = ((ssize_t)PT_REGS_RC(ctx) < 0) ? 1 : 0;
#else
    __u8 err = 0;
#endif

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_READ, 1);
#if NETDATASEL < 2
    if (err)
        libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_READ, 1);
#endif
    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_READ, libnetdata_log2l(bytes));

    if (!monitor_apps(&vfs_ctrl))
        return 0;

    struct netdata_vfs_event_t __arena *ev = bpf_ringbuf_reserve(&vfs_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_vfs_fill_event(ev, &vfs_ctrl);
    ev->bytes  = (__u64)bytes;
    ev->action = NETDATA_VFS_EVENT_READ;
    ev->error  = err;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_readv")
#else
SEC("kprobe/vfs_readv")
#endif
int netdata_sys_readv_buffer(struct pt_regs *ctx)
{
    ssize_t bytes = (ssize_t)PT_REGS_PARM3(ctx);
#if NETDATASEL < 2
    __u8 err = ((ssize_t)PT_REGS_RC(ctx) < 0) ? 1 : 0;
#else
    __u8 err = 0;
#endif

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_READV, 1);
#if NETDATASEL < 2
    if (err)
        libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_READV, 1);
#endif
    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_READV, libnetdata_log2l(bytes));

    if (!monitor_apps(&vfs_ctrl))
        return 0;

    struct netdata_vfs_event_t __arena *ev = bpf_ringbuf_reserve(&vfs_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_vfs_fill_event(ev, &vfs_ctrl);
    ev->bytes  = (__u64)bytes;
    ev->action = NETDATA_VFS_EVENT_READV;
    ev->error  = err;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_unlink")
#else
SEC("kprobe/vfs_unlink")
#endif
int netdata_sys_unlink_buffer(struct pt_regs *ctx)
{
#if NETDATASEL < 2
    __u8 err = ((int)PT_REGS_RC(ctx) < 0) ? 1 : 0;
#else
    __u8 err = 0;
#endif

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_UNLINK, 1);
#if NETDATASEL < 2
    if (err)
        libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_UNLINK, 1);
#endif

    if (!monitor_apps(&vfs_ctrl))
        return 0;

    struct netdata_vfs_event_t __arena *ev = bpf_ringbuf_reserve(&vfs_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_vfs_fill_event(ev, &vfs_ctrl);
    ev->bytes  = 0;
    ev->action = NETDATA_VFS_EVENT_UNLINK;
    ev->error  = err;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_fsync")
#else
SEC("kprobe/vfs_fsync")
#endif
int netdata_vfs_fsync_buffer(struct pt_regs *ctx)
{
#if NETDATASEL < 2
    __u8 err = ((int)PT_REGS_RC(ctx) < 0) ? 1 : 0;
#else
    __u8 err = 0;
#endif

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_FSYNC, 1);
#if NETDATASEL < 2
    if (err)
        libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_FSYNC, 1);
#endif

    if (!monitor_apps(&vfs_ctrl))
        return 0;

    struct netdata_vfs_event_t __arena *ev = bpf_ringbuf_reserve(&vfs_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_vfs_fill_event(ev, &vfs_ctrl);
    ev->bytes  = 0;
    ev->action = NETDATA_VFS_EVENT_FSYNC;
    ev->error  = err;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_open")
#else
SEC("kprobe/vfs_open")
#endif
int netdata_vfs_open_buffer(struct pt_regs *ctx)
{
#if NETDATASEL < 2
    __u8 err = ((int)PT_REGS_RC(ctx) < 0) ? 1 : 0;
#else
    __u8 err = 0;
#endif

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_OPEN, 1);
#if NETDATASEL < 2
    if (err)
        libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_OPEN, 1);
#endif

    if (!monitor_apps(&vfs_ctrl))
        return 0;

    struct netdata_vfs_event_t __arena *ev = bpf_ringbuf_reserve(&vfs_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_vfs_fill_event(ev, &vfs_ctrl);
    ev->bytes  = 0;
    ev->action = NETDATA_VFS_EVENT_OPEN;
    ev->error  = err;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_create")
#else
SEC("kprobe/vfs_create")
#endif
int netdata_vfs_create_buffer(struct pt_regs *ctx)
{
#if NETDATASEL < 2
    __u8 err = ((int)PT_REGS_RC(ctx) < 0) ? 1 : 0;
#else
    __u8 err = 0;
#endif

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_CREATE, 1);
#if NETDATASEL < 2
    if (err)
        libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_CREATE, 1);
#endif

    if (!monitor_apps(&vfs_ctrl))
        return 0;

    struct netdata_vfs_event_t __arena *ev = bpf_ringbuf_reserve(&vfs_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_vfs_fill_event(ev, &vfs_ctrl);
    ev->bytes  = 0;
    ev->action = NETDATA_VFS_EVENT_CREATE;
    ev->error  = err;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
