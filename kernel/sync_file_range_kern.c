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

struct bpf_map_def SEC("maps") tbl_syncfr = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_SYNC_END
};

/************************************************************************************
 *
 *                               SYNC_FILE_RANGE SECTION
 *
 ***********************************************************************************/

SEC("kprobe/" NETDATA_SYSCALL(sync_file_range))
int netdata_syscall_sync(struct pt_regs* ctx)
{
    libnetdata_update_global(&tbl_syncfr, NETDATA_KEY_SYNC_CALL, 1);

    return 0;
}

/************************************************************************************
 *
 *                             END SYNC_FILE_RANGE SECTION
 *
 ***********************************************************************************/

