#define KBUILD_MODNAME "swap_buffer_kern"
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
#include "netdata_arena_common.h"
#include "netdata_swap.h"
#include "netdata_swap_buffer.h"

/************************************************************************************
 *
 *                                 MAPS Section
 *
 ***********************************************************************************/

NETDATA_BPF_RINGBUF_DEF(swap_events, NETDATA_SWAP_RINGBUF_SIZE);
NETDATA_BPF_PERCPU_ARRAY_DEF(tbl_swap, __u32, __u64, NETDATA_SWAP_END);
NETDATA_BPF_ARRAY_DEF(swap_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

/************************************************************************************
 *
 *                                Local Functions
 *
 ***********************************************************************************/

static __always_inline void netdata_swap_fill_event(struct netdata_swap_event_t __arena *ev, void *ctrl)
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

#if (LINUX_VERSION_CODE > KERNEL_VERSION(6,7,255))
SEC("kprobe/swap_read_folio")
#else
SEC("kprobe/swap_readpage")
#endif
int netdata_swap_readpage_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_swap, NETDATA_KEY_SWAP_READPAGE_CALL, 1);

    if (!monitor_apps(&swap_ctrl))
        return 0;

    struct netdata_swap_event_t __arena *ev = bpf_ringbuf_reserve(&swap_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_swap_fill_event(ev, &swap_ctrl);
    ev->action = NETDATA_SWAP_EVENT_READ;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,16,0))
SEC("kprobe/__swap_writepage")
#else
SEC("kprobe/swap_writepage")
#endif
int netdata_swap_writepage_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_swap, NETDATA_KEY_SWAP_WRITEPAGE_CALL, 1);

    if (!monitor_apps(&swap_ctrl))
        return 0;

    struct netdata_swap_event_t __arena *ev = bpf_ringbuf_reserve(&swap_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_swap_fill_event(ev, &swap_ctrl);
    ev->action = NETDATA_SWAP_EVENT_WRITE;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
