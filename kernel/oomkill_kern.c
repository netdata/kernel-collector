#define KBUILD_MODNAME "oomkill_netdata"
#include <linux/ptrace.h>
#include <linux/oom.h>
#include <linux/threads.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "netdata_ebpf.h"

struct {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    __uint(type, BPF_MAP_TYPE_HASH);
#else
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#endif
    __type(key, int);
    __type(value, __u8);
    __uint(max_entries, NETDATA_OOMKILL_MAX_ENTRIES);
} tbl_oomkill SEC(".maps");

SEC("tracepoint/oom/mark_victim")
int netdata_oom_mark_victim(struct netdata_oom_mark_victim_entry *ptr) {
    int key = ptr->pid;
    u8 val = 0;
    bpf_map_update_elem(&tbl_oomkill, &key, &val, BPF_ANY);
    return 0;
}

char _license[] SEC("license") = "GPL";
