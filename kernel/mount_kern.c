#define KBUILD_MODNAME "mount_netdata"

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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_MOUNT_END);
} tbl_mount SEC(".maps");

/************************************************************************************
 *
 *                               MOUNT SECTION
 *
 ***********************************************************************************/

#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION >= 1)
#if NETDATASEL < 2
SEC("kretsyscall/mount")
#else
SEC("ksyscall/mount")
#endif /* NETDATASEL < 2 */
#else
#if NETDATASEL < 2
SEC("kretprobe/" NETDATA_SYSCALL(mount))
#else
SEC("kprobe/" NETDATA_SYSCALL(mount))
#endif /* NETDATASEL < 2 */
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

#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION >= 1)
#if NETDATASEL < 2
SEC("kretsyscall/umount")
#else
SEC("ksyscall/umount")
#endif /* NETDATASEL < 2 */
#else
#if NETDATASEL < 2
SEC("kretprobe/" NETDATA_SYSCALL(umount))
#else
SEC("kprobe/" NETDATA_SYSCALL(umount))
#endif /* NETDATASEL < 2 */
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

