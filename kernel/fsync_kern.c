#define KBUILD_MODNAME "fsync_netdata"
#include <linux/bpf.h>

#include "bpf_helpers.h"
#include "netdata_ebpf.h"

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
} tbl_fsync SEC(".maps");

/************************************************************************************
 *
 *                               FSYNC SECTION
 *
 ***********************************************************************************/

SEC("kprobe/" NETDATA_SYSCALL(fsync))
int netdata_syscall_sync(struct pt_regs* ctx)
{
    libnetdata_update_global(&tbl_fsync, NETDATA_KEY_SYNC_CALL, 1);

    return 0;
}

/************************************************************************************
 *
 *                             END FSYNC SECTION
 *
 ***********************************************************************************/

