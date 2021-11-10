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
} tbl_syncfs SEC(".maps");

/************************************************************************************
 *
 *                               SYNC SECTION (trampoline and kprobe)
 *
 ***********************************************************************************/

SEC("fentry/__x64_sys_syncfs")
int BPF_PROG(__x64_sys_syncfs_fentry)
{
    libnetdata_update_global(&tbl_syncfs, NETDATA_KEY_SYNC_CALL, 1);

    return 0;
}

SEC("kprobe/__x64_sys_syncfs")
int BPF_KPROBE(__x64_sys_syncfs_kprobe)
{
    libnetdata_update_global(&tbl_syncfs, NETDATA_KEY_SYNC_CALL, 1);

    return 0;
}

char _license[] SEC("license") = "GPL";

