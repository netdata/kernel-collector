#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "netdata_core.h"
#include "netdata_mount.h"

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
 *                     MOUNT SECTION (tracepoint)
 *
 ***********************************************************************************/

SEC("tracepoint/syscalls/sys_exit_mount")
int netdata_mount_exit(struct trace_event_raw_sys_exit *arg)
{
    libnetdata_update_global(&tbl_mount, NETDATA_KEY_MOUNT_CALL, 1);

    int ret = (int)arg->ret;
    if (ret < 0)
        libnetdata_update_global(&tbl_mount, NETDATA_KEY_MOUNT_ERROR, 1);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_umount")
int netdata_umount_exit(struct trace_event_raw_sys_exit *arg)
{
    libnetdata_update_global(&tbl_mount, NETDATA_KEY_UMOUNT_CALL, 1);

    int ret = (int)arg->ret;
    if (ret < 0)
        libnetdata_update_global(&tbl_mount, NETDATA_KEY_UMOUNT_ERROR, 1);

    return 0;
}

/************************************************************************************
 *
 *                     MOUNT SECTION (kprobe)
 *
 ***********************************************************************************/

SEC("kprobe/netdata_mount_probe")
int BPF_KPROBE(netdata_mount_probe)
{
    libnetdata_update_global(&tbl_mount, NETDATA_KEY_MOUNT_CALL, 1);

    return 0;
}

SEC("kretprobe/netdata_mount_retprobe")
int BPF_KRETPROBE(netdata_mount_retprobe)
{
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0)
        libnetdata_update_global(&tbl_mount, NETDATA_KEY_MOUNT_ERROR, 1);

    return 0;
}

SEC("kprobe/netdata_umount_probe")
int BPF_KPROBE(netdata_umount_probe)
{
    libnetdata_update_global(&tbl_mount, NETDATA_KEY_UMOUNT_CALL, 1);

    return 0;
}

SEC("kretprobe/netdata_umount_retprobe")
int BPF_KRETPROBE(netdata_umount_retprobe)
{
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0)
        libnetdata_update_global(&tbl_mount, NETDATA_KEY_UMOUNT_ERROR, 1);

    return 0;
}

/************************************************************************************
 *
 *                     MOUNT SECTION (trampoline)
 *
 ***********************************************************************************/

SEC("fentry/netdata_mount")
int BPF_PROG(netdata_mount_fentry)
{
    libnetdata_update_global(&tbl_mount, NETDATA_KEY_MOUNT_CALL, 1);

    return 0;
}

SEC("fexit/netdata_mount")
int BPF_PROG(netdata_mount_fexit, const struct pt_regs *regs)
{
    int ret = (int)PT_REGS_RC(regs);
    if (ret < 0)
        libnetdata_update_global(&tbl_mount, NETDATA_KEY_MOUNT_ERROR, 1);

    return 0;
}

SEC("fentry/netdata_umount")
int BPF_PROG(netdata_umount_fentry)
{
    libnetdata_update_global(&tbl_mount, NETDATA_KEY_UMOUNT_CALL, 1);

    return 0;
}

SEC("fexit/netdata_umount")
int BPF_PROG(netdata_umount_fexit, const struct pt_regs *regs)
{
    int ret = (int)PT_REGS_RC(regs);
    if (ret < 0)
        libnetdata_update_global(&tbl_mount, NETDATA_KEY_UMOUNT_ERROR, 1);

    return 0;
}

char _license[] SEC("license") = "GPL";

