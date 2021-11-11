#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "netdata_core.h"
#include "netdata_sync.h"

/************************************************************************************
 *
 *                                 MAPS
 *
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_SYNC_END);
} tbl_sync SEC(".maps");

/************************************************************************************
 *
 *                               SYNC SECTION (trampoline and kprobe)
 *
 ***********************************************************************************/

SEC("fentry/netdata_sync")
int BPF_PROG(netdata_sync_fentry)
{
    libnetdata_update_global(&tbl_sync, NETDATA_KEY_SYNC_CALL, 1);

    return 0;
}

SEC("kprobe/netdata_sync")
int BPF_KPROBE(netdata_sync_kprobe)
{
    libnetdata_update_global(&tbl_sync, NETDATA_KEY_SYNC_CALL, 1);

    return 0;
}

char _license[] SEC("license") = "GPL";

