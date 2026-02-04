#define KBUILD_MODNAME "cachestat_kern"
#include <linux/threads.h>
#include <linux/version.h>
#include <linux/mm_types.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include <linux/sched.h>
#include "netdata_ebpf.h"

NETDATA_BPF_PERCPU_ARRAY_DEF(cstat_global, __u32, __u64, NETDATA_CACHESTAT_END);
NETDATA_BPF_HASH_DEF(cstat_pid, __u32, netdata_cachestat_t, PID_MAX_DEFAULT);
NETDATA_BPF_ARRAY_DEF(cstat_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

static __always_inline void netdata_cachestat_update_existing(__u32 *field)
{
    if (field)
        libnetdata_update_u32(field, 1);
}

static __always_inline void netdata_cachestat_create_new_entry(__u32 *field, __u32 tgid)
{
    netdata_cachestat_t data = {};

    data.ct = bpf_ktime_get_ns();
    libnetdata_update_uid_gid(&data.uid, &data.gid);
    data.tgid = tgid;

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
    bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
    data.name[0] = '\0';
#endif

    __u32 key = 0;
    if (field)
        *field = 1;
    bpf_map_update_elem(&cstat_pid, &key, &data, BPF_ANY);

    libnetdata_update_global(&cstat_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
}

/************************************************************************************
 *
 *                                   Probe Section
 *
 ***********************************************************************************/

SEC("kprobe/add_to_page_cache_lru")
int netdata_add_to_page_cache_lru(struct pt_regs* ctx)
{
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_ADD_TO_PAGE_CACHE_LRU, 1);

    if (!monitor_apps(&cstat_ctrl))
        return 0;

    netdata_cachestat_t *fill, data = {};
    __u32 key = 0;
    __u32 tgid = 0;

    fill = netdata_get_pid_structure(&key, &tgid, &cstat_ctrl, &cstat_pid);
    if (fill) {
        netdata_cachestat_update_existing(&fill->add_to_page_cache_lru);
        return 0;
    }

    netdata_cachestat_create_new_entry(&data.add_to_page_cache_lru, tgid);

    return 0;
}

SEC("kprobe/mark_page_accessed")
int netdata_mark_page_accessed(struct pt_regs* ctx)
{
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_MARK_PAGE_ACCESSED, 1);

    if (!monitor_apps(&cstat_ctrl))
        return 0;

    netdata_cachestat_t *fill, data = {};
    __u32 key = 0;
    __u32 tgid = 0;

    fill = netdata_get_pid_structure(&key, &tgid, &cstat_ctrl, &cstat_pid);
    if (fill) {
        netdata_cachestat_update_existing(&fill->mark_page_accessed);
        return 0;
    }

    netdata_cachestat_create_new_entry(&data.mark_page_accessed, tgid);

    return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0))

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0))
SEC("kprobe/__folio_mark_dirty")
#else
SEC("kprobe/__set_page_dirty")
#endif
int netdata_set_page_dirty(struct pt_regs* ctx)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,16,0))
    struct page *page = (struct page *)PT_REGS_PARM1(ctx) ;
    struct address_space *mapping =  _(page->mapping);

    if (!mapping)
        return 0;
#endif

    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_ACCOUNT_PAGE_DIRTIED, 1);

    if (!monitor_apps(&cstat_ctrl))
        return 0;

    netdata_cachestat_t *fill, data = {};
    __u32 key = 0;
    __u32 tgid = 0;

    fill = netdata_get_pid_structure(&key, &tgid, &cstat_ctrl, &cstat_pid);
    if (fill) {
        netdata_cachestat_update_existing(&fill->account_page_dirtied);
        return 0;
    }

    netdata_cachestat_create_new_entry(&data.account_page_dirtied, tgid);

    return 0;
}
#else
#if defined(RHEL_MAJOR) && (LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0))
SEC("kprobe/__folio_mark_dirty")
#else
SEC("kprobe/account_page_dirtied")
#endif
int netdata_account_page_dirtied(struct pt_regs* ctx)
{
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_ACCOUNT_PAGE_DIRTIED, 1);

    if (!monitor_apps(&cstat_ctrl))
        return 0;

    netdata_cachestat_t *fill, data = {};
    __u32 key = 0;
    __u32 tgid = 0;

    fill = netdata_get_pid_structure(&key, &tgid, &cstat_ctrl, &cstat_pid);
    if (fill) {
        netdata_cachestat_update_existing(&fill->account_page_dirtied);
        return 0;
    }

    netdata_cachestat_create_new_entry(&data.account_page_dirtied, tgid);

    return 0;
}
#endif

SEC("kprobe/mark_buffer_dirty")
int netdata_mark_buffer_dirty(struct pt_regs* ctx)
{
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_MARK_BUFFER_DIRTY, 1);

    if (!monitor_apps(&cstat_ctrl))
        return 0;

    netdata_cachestat_t *fill, data = {};
    __u32 key = 0;
    __u32 tgid = 0;

    fill = netdata_get_pid_structure(&key, &tgid, &cstat_ctrl, &cstat_pid);
    if (fill) {
        netdata_cachestat_update_existing(&fill->mark_buffer_dirty);
        return 0;
    }

    netdata_cachestat_create_new_entry(&data.mark_buffer_dirty, tgid);

    return 0;
}

char _license[] SEC("license") = "GPL";

