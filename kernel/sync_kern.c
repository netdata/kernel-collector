#define KBUILD_MODNAME "latency_tp_netdata"
#include <linux/bpf.h>
#include <linux/ptrace.h>

#include "bpf_helpers.h"
#include "netdata_ebpf.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

struct bpf_map_def SEC("maps") tbl_sync = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_SYNC_END
};

/************************************************************************************
 *     
 *                                 GLOBAL
 *     
 ***********************************************************************************/

static void netdata_update_global(__u32 key, __u64 value)
{
    __u64 *res;
    res = bpf_map_lookup_elem(&tbl_sync, &key);
    if (res) {
        netdata_update_u64(res, value) ;
    } else
        bpf_map_update_elem(&tbl_sync, &key, &value, BPF_NOEXIST);
}


/************************************************************************************
 *
 *                               SYNC SECTION
 *
 ***********************************************************************************/

#if NETDATASEL < 2
SEC("kretprobe/" NETDATA_SYSCALL(sync))
#else
SEC("kprobe/" NETDATA_SYSCALL(sync))
#endif
int netdata_syscall_sync(struct pt_regs* ctx)
{
    netdata_update_global(NETDATA_KEY_SYNC_CALL, 1);
#if NETDATASEL < 2
    int ret = (ssize_t)PT_REGS_RC(ctx);
    if (ret < 0)
        netdata_update_global(NETDATA_KEY_SYNC_ERROR, 1);
#endif

    return 0;
}

/************************************************************************************
 *
 *                             END SYNC SECTION
 *
 ***********************************************************************************/

