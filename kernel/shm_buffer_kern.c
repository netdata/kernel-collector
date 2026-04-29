#define KBUILD_MODNAME "shm_buffer_kern"
#include <linux/version.h>
#include <linux/sched.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "netdata_common.h"
#include "netdata_shm.h"
#include "netdata_shm_buffer.h"

/************************************************************************************
 *
 *                                 MAPS Section
 *
 ***********************************************************************************/

NETDATA_BPF_RINGBUF_DEF(shm_events, NETDATA_SHM_RINGBUF_SIZE);
NETDATA_BPF_PERCPU_ARRAY_DEF(tbl_shm, __u32, __u64, NETDATA_SHM_END);
NETDATA_BPF_ARRAY_DEF(shm_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

/************************************************************************************
 *
 *                                Local Functions
 *
 ***********************************************************************************/

static __always_inline void netdata_shm_fill_event(struct netdata_shm_event_t *ev, void *ctrl)
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
    ev->pad[0] = ev->pad[1] = ev->pad[2] = 0;
}

/************************************************************************************
 *
 *                                   Probes Section
 *
 ***********************************************************************************/

#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION >= 1)
SEC("ksyscall/shmget")
#else
SEC("kprobe/" NETDATA_SYSCALL(shmget))
#endif
int netdata_syscall_shmget_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_shm, NETDATA_KEY_SHMGET_CALL, 1);

    if (!monitor_apps(&shm_ctrl))
        return 0;

    struct netdata_shm_event_t *ev = bpf_ringbuf_reserve(&shm_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_shm_fill_event(ev, &shm_ctrl);
    ev->action = NETDATA_SHM_EVENT_GET;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION >= 1)
SEC("ksyscall/shmat")
#else
SEC("kprobe/" NETDATA_SYSCALL(shmat))
#endif
int netdata_syscall_shmat_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_shm, NETDATA_KEY_SHMAT_CALL, 1);

    if (!monitor_apps(&shm_ctrl))
        return 0;

    struct netdata_shm_event_t *ev = bpf_ringbuf_reserve(&shm_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_shm_fill_event(ev, &shm_ctrl);
    ev->action = NETDATA_SHM_EVENT_AT;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION >= 1)
SEC("ksyscall/shmdt")
#else
SEC("kprobe/" NETDATA_SYSCALL(shmdt))
#endif
int netdata_syscall_shmdt_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_shm, NETDATA_KEY_SHMDT_CALL, 1);

    if (!monitor_apps(&shm_ctrl))
        return 0;

    struct netdata_shm_event_t *ev = bpf_ringbuf_reserve(&shm_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_shm_fill_event(ev, &shm_ctrl);
    ev->action = NETDATA_SHM_EVENT_DT;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION >= 1)
SEC("ksyscall/shmctl")
#else
SEC("kprobe/" NETDATA_SYSCALL(shmctl))
#endif
int netdata_syscall_shmctl_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_shm, NETDATA_KEY_SHMCTL_CALL, 1);

    if (!monitor_apps(&shm_ctrl))
        return 0;

    struct netdata_shm_event_t *ev = bpf_ringbuf_reserve(&shm_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_shm_fill_event(ev, &shm_ctrl);
    ev->action = NETDATA_SHM_EVENT_CTL;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
