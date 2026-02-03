#define KBUILD_MODNAME "msync_netdata"

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

NETDATA_BPF_ARRAY_DEF(tbl_msync, __u32, __u64, NETDATA_SYNC_END);

/************************************************************************************
 *
 *                               MSYNC SECTION
 *
 ***********************************************************************************/

#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION >= 1)
SEC("ksyscall/msync")
#else
SEC("kprobe/" NETDATA_SYSCALL(msync))
#endif
int netdata_syscall_sync(struct pt_regs* ctx)
{
    libnetdata_update_global(&tbl_msync, NETDATA_KEY_SYNC_CALL, 1);

    return 0;
}

/************************************************************************************
 *
 *                             END MSYNC SECTION
 *
 ***********************************************************************************/

