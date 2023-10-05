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

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_CACHESTAT_END);
} cstat_global  SEC(".maps");

struct {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    __uint(type, BPF_MAP_TYPE_HASH);
#else
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#endif
    __type(key, __u32);
    __type(value, netdata_cachestat_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} cstat_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} cstat_ctrl SEC(".maps");

#else

struct bpf_map_def SEC("maps") cstat_global = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_CACHESTAT_END
};

struct bpf_map_def SEC("maps") cstat_pid = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(netdata_cachestat_t),
    .max_entries = PID_MAX_DEFAULT
};

struct bpf_map_def SEC("maps") cstat_ctrl = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_CONTROLLER_END
};

#endif

/************************************************************************************
 *
 *                                   Probe Section
 *
 ***********************************************************************************/

SEC("kprobe/add_to_page_cache_lru")
int netdata_add_to_page_cache_lru(struct pt_regs* ctx)
{
    netdata_cachestat_t *fill, data = {};
    libnetdata_update_global(&cstat_global, NETDATA_KEY_MISSES, 1);

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&cstat_ctrl))
        return 0;

    fill = netdata_get_pid_structure(&key, &tgid, &cstat_ctrl, &cstat_pid);
    if (fill) {
        libnetdata_update_s64(&fill->misses, 1);
    } else {
        data.ct = bpf_ktime_get_ns();
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif

        data.misses = 1;
        bpf_map_update_elem(&cstat_pid, &key, &data, BPF_ANY);

        libnetdata_update_global(&cstat_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

SEC("kprobe/mark_page_accessed")
int netdata_mark_page_accessed(struct pt_regs* ctx)
{
    netdata_cachestat_t *fill, data = {};
    libnetdata_update_global(&cstat_global, NETDATA_KEY_TOTAL, 1);

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&cstat_ctrl))
        return 0;

    fill = netdata_get_pid_structure(&key, &tgid, &cstat_ctrl, &cstat_pid);
    if (fill) {
        libnetdata_update_s64(&fill->total, 1);
    } else {
        data.ct = bpf_ktime_get_ns();
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif

        data.total = 1;
        bpf_map_update_elem(&cstat_pid, &key, &data, BPF_ANY);

        libnetdata_update_global(&cstat_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0))

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0))
// When kernel 5.16.0 was released, __set_page_dirty became a static inline function,
// so we are callging directly the __folio_mark_dirty.
SEC("kprobe/__folio_mark_dirty")
#else
// When kernel 5.15.0 was released the function account_page_dirtied became static
// https://elixir.bootlin.com/linux/v5.15/source/mm/page-writeback.c#L2441
// as consequence of this, we are monitoring the function from caller.
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

    netdata_cachestat_t *fill, data = {};
    libnetdata_update_sglobal(&cstat_global, NETDATA_KEY_MISSES, -1);

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&cstat_ctrl))
        return 0;

    fill = netdata_get_pid_structure(&key, &tgid, &cstat_ctrl, &cstat_pid);
    if (fill) {
        libnetdata_update_s64(&fill->misses, -1);
    } else {
        data.ct = bpf_ktime_get_ns();
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif

        data.misses = -1;
        bpf_map_update_elem(&cstat_pid, &key, &data, BPF_ANY);

        libnetdata_update_global(&cstat_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
    }

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
    netdata_cachestat_t *fill, data = {};
    libnetdata_update_sglobal(&cstat_global, NETDATA_KEY_MISSES, -1);

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&cstat_ctrl))
        return 0;

    fill = netdata_get_pid_structure(&key, &tgid, &cstat_ctrl, &cstat_pid);
    if (fill) {
        libnetdata_update_s64(&fill->misses, -1);
    } else {
        data.ct = bpf_ktime_get_ns();
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif

        data.misses = -1;
        bpf_map_update_elem(&cstat_pid, &key, &data, BPF_ANY);

        libnetdata_update_global(&cstat_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}
#endif

SEC("kprobe/mark_buffer_dirty")
int netdata_mark_buffer_dirty(struct pt_regs* ctx)
{
    netdata_cachestat_t *fill, data = {};
    libnetdata_update_sglobal(&cstat_global, NETDATA_KEY_TOTAL, -1);
    libnetdata_update_global(&cstat_global, NETDATA_KEY_DIRTY, 1);

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&cstat_ctrl))
        return 0;

    fill = netdata_get_pid_structure(&key, &tgid, &cstat_ctrl, &cstat_pid);
    if (fill) {
        libnetdata_update_u64(&fill->total, -1);
        libnetdata_update_u64(&fill->dirty, 1);
    } else {
        data.ct = bpf_ktime_get_ns();
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif

        data.dirty = 1;
        data.total = -1;
        bpf_map_update_elem(&cstat_pid, &key, &data, BPF_ANY);

        libnetdata_update_global(&cstat_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

