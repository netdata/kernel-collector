#define KBUILD_MODNAME "latency_tp_netdata"
#include <linux/bpf.h>
#include <linux/ptrace.h>

#include "netdata_ebpf.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

struct bpf_map_def SEC("maps") tbl_sync = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_SYNC_END
};


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

