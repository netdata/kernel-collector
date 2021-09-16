#define KBUILD_MODNAME "oomkill_netdata"
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/oom.h>
#include <linux/threads.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,4,14))
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#else
#include "netdata_bpf_helpers.h"
#endif
#include "netdata_ebpf.h"

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,4,14))
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, int);
    __type(value, __u8);
    __uint(max_entries, NETDATA_OOMKILL_MAX_ENTRIES);
} tbl_oomkill SEC(".maps");
#else
struct bpf_map_def SEC("maps") tbl_oomkill = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(int),
    .value_size = sizeof(__u8),
    .max_entries = NETDATA_OOMKILL_MAX_ENTRIES
};
#endif

SEC("tracepoint/oom/mark_victim")
int netdata_oom_mark_victim(struct netdata_oom_mark_victim_entry *ptr) {
    int key = ptr->pid;
    u8 val = 0;
    bpf_map_update_elem(&tbl_oomkill, &key, &val, BPF_ANY);
    return 0;
}

char _license[] SEC("license") = "GPL";
