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

SEC("tracepoint/syscalls/sys_enter_syncfs")
int netdata_syncfs_entry(struct trace_event_raw_sys_enter *ctx)
{
    libnetdata_update_global(&tbl_sync, NETDATA_KEY_SYNC_CALL, 1);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_msync")
int netdata_msync_entry(struct trace_event_raw_sys_enter *ctx)
{
    libnetdata_update_global(&tbl_sync, NETDATA_KEY_SYNC_CALL, 1);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sync_file_range")
int netdata_sync_file_range_entry(struct trace_event_raw_sys_enter *ctx)
{
    libnetdata_update_global(&tbl_sync, NETDATA_KEY_SYNC_CALL, 1);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsync")
int netdata_fsync_entry(struct trace_event_raw_sys_enter *ctx)
{
    libnetdata_update_global(&tbl_sync, NETDATA_KEY_SYNC_CALL, 1);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fdatasync")
int netdata_fdatasync_entry(struct trace_event_raw_sys_enter *ctx)
{
    libnetdata_update_global(&tbl_sync, NETDATA_KEY_SYNC_CALL, 1);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sync")
int netdata_sync_entry(struct trace_event_raw_sys_enter *ctx)
{
    libnetdata_update_global(&tbl_sync, NETDATA_KEY_SYNC_CALL, 1);

    return 0;
}


char _license[] SEC("license") = "GPL";

