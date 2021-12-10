#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "netdata_core.h"
#include "netdata_oomkill.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, int);
    __type(value, __u8);
    __uint(max_entries, NETDATA_OOMKILL_MAX_ENTRIES);
} tbl_oomkill SEC(".maps");

/***********************************************************************************
 *
 *                        OOMKILL SECTION(tracepoint)
 *
 ***********************************************************************************/

SEC("tracepoint/oom/mark_victim")
int netdata_oom_mark_victim(struct netdata_oom_mark_victim_entry *ptr) {
    int key = ptr->pid;
    u8 val = 0;
    bpf_map_update_elem(&tbl_oomkill, &key, &val, BPF_ANY);
    return 0;
}

char _license[] SEC("license") = "GPL";

