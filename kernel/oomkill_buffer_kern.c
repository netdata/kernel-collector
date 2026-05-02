#define KBUILD_MODNAME "oomkill_buffer_kern"
#include <linux/ptrace.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "netdata_common.h"
#include "netdata_arena_common.h"
#include "netdata_oomkill.h"
#include "netdata_oomkill_buffer.h"

/************************************************************************************
 *
 *                                 MAPS Section
 *
 ***********************************************************************************/

NETDATA_BPF_RINGBUF_DEF(oomkill_events, NETDATA_OOMKILL_RINGBUF_SIZE);

/************************************************************************************
 *
 *                                   Probe Section
 *
 ***********************************************************************************/

SEC("tracepoint/oom/mark_victim")
int netdata_oom_mark_victim_buffer(struct netdata_oom_mark_victim_entry *ptr)
{
    struct netdata_oomkill_event_t __arena *ev = bpf_ringbuf_reserve(&oomkill_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    __u32 pid;
    ev->ct  = bpf_ktime_get_ns();
    ev->pad = 0;
    bpf_probe_read(&pid, sizeof(pid), &ptr->pid);
    ev->pid = pid;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
