#define KBUILD_MODNAME "vfs_kern"
#include <linux/version.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,10,17))
# include <linux/sched/task.h>
#endif
#include <linux/threads.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "netdata_ebpf.h"

NETDATA_BPF_HASH_DEF(tbl_vfs_pid, __u32, struct netdata_vfs_stat_t, PID_MAX_DEFAULT);
NETDATA_BPF_PERCPU_ARRAY_DEF(tbl_vfs_stats, __u32, __u64, NETDATA_VFS_COUNTER);
NETDATA_BPF_ARRAY_DEF(vfs_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

static __always_inline void netdata_update_vfs_err(__u32 *err_field, int is_error)
{
#if NETDATASEL < 2
    if (is_error)
        libnetdata_update_u32(err_field, 1);
#endif
}

static __always_inline void netdata_update_vfs_bytes(__u64 *byte_field, __u64 bytes, int has_bytes)
{
#if NETDATASEL < 2
    if (has_bytes)
        libnetdata_update_u64(byte_field, bytes);
#endif
}

static __always_inline void netdata_init_vfs_data(struct netdata_vfs_stat_t *data, __u32 tgid)
{
    data->ct = bpf_ktime_get_ns();
    libnetdata_update_uid_gid(&data->uid, &data->gid);
    data->tgid = tgid;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
    bpf_get_current_comm(&data->name, TASK_COMM_LEN);
#else
    data->name[0] = '\0';
#endif
}

static __always_inline void netdata_update_vfs_entry(struct netdata_vfs_stat_t *fill,
                                                     struct netdata_vfs_stat_t *data,
                                                     __u32 *key,
                                                     __u32 tgid,
                                                     __u32 *call_field,
                                                     __u32 *err_field,
                                                     __u64 *byte_field,
                                                     __u64 tot,
                                                     int has_error,
                                                     int is_error,
                                                     int has_bytes)
{
    if (fill) {
        libnetdata_update_u32(call_field, 1);
        if (has_error && is_error)
            libnetdata_update_u32(err_field, 1);
        if (has_bytes)
            libnetdata_update_u64(byte_field, tot);
    } else {
        netdata_init_vfs_data(data, tgid);
        data->write_call = 0;
        data->writev_call = 0;
        data->read_call = 0;
        data->readv_call = 0;
        data->unlink_call = 0;
        data->fsync_call = 0;
        data->open_call = 0;
        data->create_call = 0;
        libnetdata_update_u32(call_field, 1);
        netdata_update_vfs_err(err_field, is_error);
        netdata_update_vfs_bytes(byte_field, tot, has_bytes);
        bpf_map_update_elem(&tbl_vfs_pid, key, data, BPF_ANY);
        libnetdata_update_global(&vfs_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
    }
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_write")
#else
SEC("kprobe/vfs_write")
#endif
int netdata_sys_write(struct pt_regs* ctx)
{
    ssize_t ret = 0;
#if NETDATASEL < 2
    ret = (ssize_t)PT_REGS_RC(ctx);
#endif
    struct netdata_vfs_stat_t data = { };
    __u64 tot = 0;

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_WRITE, 1);
#if NETDATASEL < 2
    if (ret < 0)
        libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_WRITE, 1);
#endif
    ret = (ssize_t)PT_REGS_PARM3(ctx);
    tot = libnetdata_log2l(ret);
    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_WRITE, tot);

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&vfs_ctrl))
        return 0;

    struct netdata_vfs_stat_t *fill = netdata_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    netdata_update_vfs_entry(fill, &data, &key, tgid,
                             &fill->write_call, &fill->write_err, &fill->write_bytes, tot,
                             1, ret < 0, 1);
    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_writev")
#else
SEC("kprobe/vfs_writev")
#endif
int netdata_sys_writev(struct pt_regs* ctx)
{
    ssize_t ret = 0;
#if NETDATASEL < 2
    ret = (ssize_t)PT_REGS_RC(ctx);
#endif
    struct netdata_vfs_stat_t data = { };
    __u64 tot = 0;

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_WRITEV, 1);
#if NETDATASEL < 2
    if (ret < 0)
        libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_WRITEV, 1);
#endif
    ret = (ssize_t)PT_REGS_PARM3(ctx);
    tot = libnetdata_log2l(ret);
    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_WRITEV, tot);

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&vfs_ctrl))
        return 0;

    struct netdata_vfs_stat_t *fill = netdata_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    netdata_update_vfs_entry(fill, &data, &key, tgid,
                             &fill->writev_call, &fill->writev_err, &fill->writev_bytes, tot,
                             1, ret < 0, 1);
    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_read")
#else
SEC("kprobe/vfs_read")
#endif
int netdata_sys_read(struct pt_regs* ctx)
{
    ssize_t ret = 0;
#if NETDATASEL < 2
    ret = (ssize_t)PT_REGS_RC(ctx);
#endif
    struct netdata_vfs_stat_t data = { };
    __u64 tot = 0;

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_READ, 1);
#if NETDATASEL < 2
    if (ret < 0)
        libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_READ, 1);
#endif
    ret = (ssize_t)PT_REGS_PARM3(ctx);
    tot = libnetdata_log2l(ret);
    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_READ, tot);

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&vfs_ctrl))
        return 0;

    struct netdata_vfs_stat_t *fill = netdata_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    netdata_update_vfs_entry(fill, &data, &key, tgid,
                             &fill->read_call, &fill->read_err, &fill->read_bytes, tot,
                             1, ret < 0, 1);
    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_readv")
#else
SEC("kprobe/vfs_readv")
#endif
int netdata_sys_readv(struct pt_regs* ctx)
{
    ssize_t ret = 0;
#if NETDATASEL < 2
    ret = (ssize_t)PT_REGS_RC(ctx);
#endif
    struct netdata_vfs_stat_t data = { };
    __u64 tot = 0;

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_READV, 1);
#if NETDATASEL < 2
    if (ret < 0)
        libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_READV, 1);
#endif
    ret = (ssize_t)PT_REGS_PARM3(ctx);
    tot = libnetdata_log2l(ret);
    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_READV, tot);

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&vfs_ctrl))
        return 0;

    struct netdata_vfs_stat_t *fill = netdata_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    netdata_update_vfs_entry(fill, &data, &key, tgid,
                             &fill->readv_call, &fill->readv_err, &fill->readv_bytes, tot,
                             1, ret < 0, 1);
    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_unlink")
#else
SEC("kprobe/vfs_unlink")
#endif
int netdata_sys_unlink(struct pt_regs* ctx)
{
    int ret = 0;
#if NETDATASEL < 2
    ret = (int)PT_REGS_RC(ctx);
#endif
    struct netdata_vfs_stat_t data = { };

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_UNLINK, 1);
#if NETDATASEL < 2
    if (ret < 0)
        libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_UNLINK, 1);
#endif

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&vfs_ctrl))
        return 0;

    struct netdata_vfs_stat_t *fill = netdata_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    netdata_update_vfs_entry(fill, &data, &key, tgid,
                             &fill->unlink_call, &fill->unlink_err, NULL, 0,
                             1, ret < 0, 0);
    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_fsync")
#else
SEC("kprobe/vfs_fsync")
#endif
int netdata_vfs_fsync(struct pt_regs* ctx)
{
    int ret = 0;
#if NETDATASEL < 2
    ret = (int)PT_REGS_RC(ctx);
#endif
    struct netdata_vfs_stat_t data = { };

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_FSYNC, 1);
#if NETDATASEL < 2
    if (ret < 0)
        libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_FSYNC, 1);
#endif

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&vfs_ctrl))
        return 0;

    struct netdata_vfs_stat_t *fill = netdata_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    netdata_update_vfs_entry(fill, &data, &key, tgid,
                             &fill->fsync_call, &fill->fsync_err, NULL, 0,
                             1, ret < 0, 0);
    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_open")
#else
SEC("kprobe/vfs_open")
#endif
int netdata_vfs_open(struct pt_regs* ctx)
{
    int ret = 0;
#if NETDATASEL < 2
    ret = (int)PT_REGS_RC(ctx);
#endif
    struct netdata_vfs_stat_t data = { };

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_OPEN, 1);
#if NETDATASEL < 2
    if (ret < 0)
        libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_OPEN, 1);
#endif

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&vfs_ctrl))
        return 0;

    struct netdata_vfs_stat_t *fill = netdata_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    netdata_update_vfs_entry(fill, &data, &key, tgid,
                             &fill->open_call, &fill->open_err, NULL, 0,
                             1, ret < 0, 0);
    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_create")
#else
SEC("kprobe/vfs_create")
#endif
int netdata_vfs_create(struct pt_regs* ctx)
{
    int ret = 0;
#if NETDATASEL < 2
    ret = (int)PT_REGS_RC(ctx);
#endif
    struct netdata_vfs_stat_t data = { };

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_CREATE, 1);
#if NETDATASEL < 2
    if (ret < 0)
        libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_CREATE, 1);
#endif

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&vfs_ctrl))
        return 0;

    struct netdata_vfs_stat_t *fill = netdata_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    netdata_update_vfs_entry(fill, &data, &key, tgid,
                             &fill->create_call, &fill->create_err, NULL, 0,
                             1, ret < 0, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
