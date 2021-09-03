#define KBUILD_MODNAME "mount_netdata"
#include <linux/bpf.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,4,14))
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#else
#include "netdata_bpf_helpers.h"
#endif
#include "netdata_ebpf.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,4,14))
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_MOUNT_END);
} tbl_mount SEC(".maps");
#else
struct bpf_map_def SEC("maps") tbl_mount = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_MOUNT_END
};
#endif

/************************************************************************************
 *
 *                               MOUNT SECTION
 *
 ***********************************************************************************/

#if NETDATASEL < 2
SEC("kretprobe/" NETDATA_SYSCALL(mount))
#else
SEC("kprobe/" NETDATA_SYSCALL(mount))
#endif
int netdata_syscall_mount(struct pt_regs* ctx)
{
    libnetdata_update_global(&tbl_mount, NETDATA_KEY_MOUNT_CALL, 1);
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0)
        libnetdata_update_global(&tbl_mount, NETDATA_KEY_MOUNT_ERROR, 1);
#endif

    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/" NETDATA_SYSCALL(umount))
#else
SEC("kprobe/" NETDATA_SYSCALL(umount))
#endif
int netdata_syscall_umount(struct pt_regs* ctx)
{
    libnetdata_update_global(&tbl_mount, NETDATA_KEY_UMOUNT_CALL, 1);
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0)
        libnetdata_update_global(&tbl_mount, NETDATA_KEY_UMOUNT_ERROR, 1);
#endif

    return 0;
}

/************************************************************************************
 *
 *                             END MOUNT SECTION
 *
 ***********************************************************************************/

char _license[] SEC("license") = "GPL";

