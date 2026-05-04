#define KBUILD_MODNAME "cachestat_buffer_kern"
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/mm_types.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "netdata_common.h"
#include "netdata_arena_common.h"
#include "netdata_cache.h"
#include "netdata_cache_buffer.h"

/************************************************************************************
 *
 *                                 MAPS Section
 *
 ***********************************************************************************/

NETDATA_BPF_RINGBUF_DEF(cachestat_events, NETDATA_CACHESTAT_RINGBUF_SIZE);
NETDATA_BPF_PERCPU_ARRAY_DEF(cstat_global, __u32, __u64, NETDATA_CACHESTAT_END);
NETDATA_BPF_ARRAY_DEF(cstat_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

/************************************************************************************
 *
 *                                Local Functions
 *
 ***********************************************************************************/

static __always_inline void netdata_cachestat_fill_event(struct netdata_cachestat_event_t __arena *ev, void *ctrl)
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

SEC("kprobe/add_to_page_cache_lru")
int netdata_add_to_page_cache_lru_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_ADD_TO_PAGE_CACHE_LRU, 1);

    if (!monitor_apps(&cstat_ctrl))
        return 0;

    struct netdata_cachestat_event_t __arena *ev = bpf_ringbuf_reserve(&cachestat_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_cachestat_fill_event(ev, &cstat_ctrl);
    ev->action = NETDATA_CACHESTAT_EVENT_PAGE_CACHE_LRU;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kprobe/mark_page_accessed")
int netdata_mark_page_accessed_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_MARK_PAGE_ACCESSED, 1);

    if (!monitor_apps(&cstat_ctrl))
        return 0;

    struct netdata_cachestat_event_t __arena *ev = bpf_ringbuf_reserve(&cachestat_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_cachestat_fill_event(ev, &cstat_ctrl);
    ev->action = NETDATA_CACHESTAT_EVENT_PAGE_ACCESSED;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0))

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0))
SEC("kprobe/__folio_mark_dirty")
#else
SEC("kprobe/__set_page_dirty")
#endif
int netdata_set_page_dirty_buffer(struct pt_regs *ctx)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,16,0))
    /* On 5.15, skip anonymous pages that have no backing store. */
    struct page *page = (struct page *)PT_REGS_PARM1(ctx);
    struct address_space *mapping = _(page->mapping);
    if (!mapping)
        return 0;
#endif

    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_ACCOUNT_PAGE_DIRTIED, 1);

    if (!monitor_apps(&cstat_ctrl))
        return 0;

    struct netdata_cachestat_event_t __arena *ev = bpf_ringbuf_reserve(&cachestat_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_cachestat_fill_event(ev, &cstat_ctrl);
    ev->action = NETDATA_CACHESTAT_EVENT_PAGE_DIRTIED;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

#else  /* < 5.15.0 */

#if defined(RHEL_MAJOR) && (LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0))
SEC("kprobe/__folio_mark_dirty")
#else
SEC("kprobe/account_page_dirtied")
#endif
int netdata_account_page_dirtied_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_ACCOUNT_PAGE_DIRTIED, 1);

    if (!monitor_apps(&cstat_ctrl))
        return 0;

    struct netdata_cachestat_event_t __arena *ev = bpf_ringbuf_reserve(&cachestat_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_cachestat_fill_event(ev, &cstat_ctrl);
    ev->action = NETDATA_CACHESTAT_EVENT_PAGE_DIRTIED;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

#endif  /* LINUX_VERSION_CODE >= 5.15.0 */

SEC("kprobe/mark_buffer_dirty")
int netdata_mark_buffer_dirty_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_MARK_BUFFER_DIRTY, 1);

    if (!monitor_apps(&cstat_ctrl))
        return 0;

    struct netdata_cachestat_event_t __arena *ev = bpf_ringbuf_reserve(&cachestat_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_cachestat_fill_event(ev, &cstat_ctrl);
    ev->action = NETDATA_CACHESTAT_EVENT_BUFFER_DIRTY;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
