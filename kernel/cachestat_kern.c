#define KBUILD_MODNAME "cachestat_kern"
#include <linux/bpf.h>

#include <linux/threads.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,4,14))
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#else
#include "netdata_bpf_helpers.h"
#endif
#include "netdata_ebpf.h"

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,4,14))
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_CACHESTAT_END);
} cstat_global  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, netdata_cachestat_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} cstat_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
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
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u32),
    .value_size = sizeof(netdata_cachestat_t),
    .max_entries = PID_MAX_DEFAULT
};

struct bpf_map_def SEC("maps") cstat_ctrl = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
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
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_ADD_TO_PAGE_CACHE_LRU, 1);

    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&cstat_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    fill = bpf_map_lookup_elem(&cstat_pid ,&key);
    if (fill) {
        libnetdata_update_u64(&fill->add_to_page_cache_lru, 1);
    } else {
        data.add_to_page_cache_lru = 1;
        bpf_map_update_elem(&cstat_pid, &key, &data, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/mark_page_accessed")
int netdata_mark_page_accessed(struct pt_regs* ctx)
{
    netdata_cachestat_t *fill, data = {};
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_MARK_PAGE_ACCESSED, 1);

    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&cstat_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    fill = bpf_map_lookup_elem(&cstat_pid ,&key);
    if (fill) {
        libnetdata_update_u64(&fill->mark_page_accessed, 1);
    } else {
        data.mark_page_accessed = 1;
        bpf_map_update_elem(&cstat_pid, &key, &data, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/account_page_dirtied")
int netdata_account_page_dirtied(struct pt_regs* ctx)
{
    netdata_cachestat_t *fill, data = {};
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_ACCOUNT_PAGE_DIRTIED, 1);

    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&cstat_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    fill = bpf_map_lookup_elem(&cstat_pid ,&key);
    if (fill) {
        libnetdata_update_u64(&fill->account_page_dirtied, 1);
    } else {
        data.account_page_dirtied = 1;
        bpf_map_update_elem(&cstat_pid, &key, &data, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/mark_buffer_dirty")
int netdata_mark_buffer_dirty(struct pt_regs* ctx)
{
    netdata_cachestat_t *fill, data = {};
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_MARK_BUFFER_DIRTY, 1);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    fill = bpf_map_lookup_elem(&cstat_pid ,&pid);
    if (fill) {
        libnetdata_update_u64(&fill->mark_buffer_dirty, 1);
    } else {
        data.mark_buffer_dirty = 1;
        bpf_map_update_elem(&cstat_pid, &pid, &data, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

