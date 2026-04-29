#define KBUILD_MODNAME "dc_buffer_kern"
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
#include "netdata_dc.h"
#include "netdata_dc_buffer.h"

/************************************************************************************
 *
 *                                 MAPS Section
 *
 ***********************************************************************************/

NETDATA_BPF_RINGBUF_DEF(dc_events, NETDATA_DC_RINGBUF_SIZE);
NETDATA_BPF_PERCPU_ARRAY_DEF(dcstat_global, __u32, __u64, NETDATA_DIRECTORY_CACHE_END);
NETDATA_BPF_PERCPU_ARRAY_DEF(dcstat_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

/************************************************************************************
 *
 *                                Local Functions
 *
 ***********************************************************************************/

static __always_inline void netdata_dc_fill_event(struct netdata_dc_event_t *ev, void *ctrl)
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

SEC("kprobe/lookup_fast")
int netdata_lookup_fast_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&dcstat_global, NETDATA_KEY_DC_REFERENCE, 1);

    if (!monitor_apps(&dcstat_ctrl))
        return 0;

    struct netdata_dc_event_t *ev = bpf_ringbuf_reserve(&dc_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_dc_fill_event(ev, &dcstat_ctrl);
    ev->action = NETDATA_DC_EVENT_REFERENCE;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kretprobe/d_lookup")
int netdata_d_lookup_buffer(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);

    libnetdata_update_global(&dcstat_global, NETDATA_KEY_DC_SLOW, 1);
    if (ret == 0)
        libnetdata_update_global(&dcstat_global, NETDATA_KEY_DC_MISS, 1);

    if (!monitor_apps(&dcstat_ctrl))
        return 0;

    struct netdata_dc_event_t *ev = bpf_ringbuf_reserve(&dc_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_dc_fill_event(ev, &dcstat_ctrl);
    /*
     * ret == 0 means d_lookup found nothing (cache miss).
     * Encode both slow-path and miss in a single event to avoid a second reserve/submit.
     */
    ev->action = (ret == 0) ? NETDATA_DC_EVENT_SLOW_MISS : NETDATA_DC_EVENT_SLOW;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
