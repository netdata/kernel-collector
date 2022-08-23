#define KBUILD_MODNAME "sfrange_netdata"

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "netdata_ebpf.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_SYNC_END);
} tbl_syncfr SEC(".maps");
#else
struct bpf_map_def SEC("maps") tbl_syncfr = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_SYNC_END
};
#endif

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

