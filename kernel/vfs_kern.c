#define KBUILD_MODNAME "vfs_kern"
#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,10,17))
# include <linux/sched/task.h>
#endif

#include <linux/threads.h>
#include <linux/version.h>

#include "bpf_helpers.h"
#include "netdata_ebpf.h"

/************************************************************************************
 *     
 *                                 MAPS Section
 *     
 ***********************************************************************************/

struct bpf_map_def SEC("maps") tbl_vfs_pid = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct netdata_vfs_stat_t),
    .max_entries = PID_MAX_DEFAULT
};

struct bpf_map_def SEC("maps") tbl_vfs_stats = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)) 
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries =  NETDATA_VFS_COUNTER
};

/************************************************************************************
 *     
 *                                 REMOVE Section
 *     
 ***********************************************************************************/


static void netdata_update_u32(u32 *res, u32 value) 
{
    if (!value)
        return;

    __sync_fetch_and_add(res, value);
    if ( (0xFFFFFFFFFFFFFFFF - *res) <= value) {
        *res = value;
    }
}

/************************************************************************************
 *     
 *                                   FILE Section
 *     
 ***********************************************************************************/

#if NETDATASEL < 2
SEC("kretprobe/vfs_write")
#else
SEC("kprobe/vfs_write")
#endif
int netdata_sys_write(struct pt_regs* ctx)
{
    ssize_t ret;
#if NETDATASEL < 2
    ret = (ssize_t)PT_REGS_RC(ctx);
#endif
    struct netdata_vfs_stat_t *fill;
    struct netdata_vfs_stat_t data = { };
    __u64 tot;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);


    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_WRITE, 1);
    fill = bpf_map_lookup_elem(&tbl_vfs_pid ,&pid);
    if (fill) {
        netdata_update_u32(&fill->write_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_WRITE, 1);
            netdata_update_u32(&fill->write_err, 1) ;
        } else {
#endif
            ret = (ssize_t)PT_REGS_PARM3(ctx);
            tot = libnetdata_log2l(ret);
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_WRITE, tot);
            libnetdata_update_u64(&fill->write_bytes, tot);
#if NETDATASEL < 2
        }
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_WRITE, 1);
            data.write_err = 1;
        } else {
#endif
            ret = (ssize_t)PT_REGS_PARM3(ctx);
            tot = libnetdata_log2l(ret);
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_WRITE, tot);
            data.write_bytes = tot;
#if NETDATASEL < 2
        }
#endif
        data.write_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &pid, &data, BPF_ANY);
    }

    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_writev")
#else
SEC("kprobe/vfs_writev")
#endif
int netdata_sys_writev(struct pt_regs* ctx)
{
    ssize_t ret;
#if NETDATASEL < 2
    ret = (ssize_t)PT_REGS_RC(ctx);
#endif
    struct netdata_vfs_stat_t *fill;
    struct netdata_vfs_stat_t data = { };
    __u64 tot;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_WRITEV, 1);
    fill = bpf_map_lookup_elem(&tbl_vfs_pid ,&pid);
    if (fill) {
        netdata_update_u32(&fill->writev_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_WRITEV, 1);
            netdata_update_u32(&fill->writev_err, 1) ;
        } else {
#endif
            ret = (ssize_t)PT_REGS_PARM3(ctx);
            tot = libnetdata_log2l(ret);
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_WRITEV, tot);
            libnetdata_update_u64(&fill->writev_bytes, tot);
#if NETDATASEL < 2
        }
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_WRITEV, 1);
            data.writev_err = 1;
        } else {
#endif
            ret = (ssize_t)PT_REGS_PARM3(ctx);
            tot = libnetdata_log2l(ret);
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_WRITEV, tot);
            data.writev_bytes = (unsigned long)tot;
#if NETDATASEL < 2
        }
#endif
        data.writev_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &pid, &data, BPF_ANY);
    }

    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_read")
#else
SEC("kprobe/vfs_read")
#endif
int netdata_sys_read(struct pt_regs* ctx)
{
    ssize_t ret;
#if NETDATASEL < 2
    ret = (ssize_t)PT_REGS_RC(ctx);
#endif
    struct netdata_vfs_stat_t *fill;
    struct netdata_vfs_stat_t data = { };
    __u64 tot;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_READ, 1);
    fill = bpf_map_lookup_elem(&tbl_vfs_pid ,&pid);
    if (fill) {
        netdata_update_u32(&fill->read_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_READ, 1);
            netdata_update_u32(&fill->read_err, 1) ;
        } else {
#endif
            ret = (ssize_t)PT_REGS_PARM3(ctx);
            tot = libnetdata_log2l(ret);
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_READ, tot);
            libnetdata_update_u64(&fill->read_bytes, tot);
#if NETDATASEL < 2
        }
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_READ, 1);
            data.read_err = 1;
        } else {
#endif
            ret = (ssize_t)PT_REGS_PARM3(ctx);
            tot = libnetdata_log2l(ret);
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_READ, tot);
            data.read_bytes = (unsigned long)tot;
#if NETDATASEL < 2
        }
#endif
        data.read_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &pid, &data, BPF_ANY);
    }

    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_readv")
#else
SEC("kprobe/vfs_readv")
#endif
int netdata_sys_readv(struct pt_regs* ctx)
{
    ssize_t ret;
#if NETDATASEL < 2
    ret = (ssize_t)PT_REGS_RC(ctx);
#endif
    struct netdata_vfs_stat_t *fill;
    struct netdata_vfs_stat_t data = { };
    __u64 tot;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_READV, 1);
    fill = bpf_map_lookup_elem(&tbl_vfs_pid ,&pid);
    if (fill) {
        netdata_update_u32(&fill->readv_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_READV, 1);
            netdata_update_u32(&fill->readv_err, 1) ;
        } else {
#endif
            ret = (ssize_t)PT_REGS_PARM3(ctx);
            tot = libnetdata_log2l(ret);
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_READV, tot);
            libnetdata_update_u64(&fill->readv_bytes, tot);
#if NETDATASEL < 2
        }
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_READV, 1);
            data.readv_err = 1;
        } else {
#endif
            ret = (ssize_t)PT_REGS_PARM3(ctx);
            tot = libnetdata_log2l(ret);
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_READV, tot);
            data.readv_bytes = (unsigned long)tot;
#if NETDATASEL < 2
        }
#endif
        data.readv_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &pid, &data, BPF_ANY);
    }

    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_unlink")
#else
SEC("kprobe/vfs_unlink")
#endif
int netdata_sys_unlink(struct pt_regs* ctx)
{
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    struct netdata_vfs_stat_t data = { };
    struct netdata_vfs_stat_t *fill;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_UNLINK, 1);
    fill = bpf_map_lookup_elem(&tbl_vfs_pid ,&pid);
    if (fill) {
        netdata_update_u32(&fill->unlink_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_UNLINK, 1);
            netdata_update_u32(&fill->unlink_err, 1) ;
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_UNLINK, 1);
            data.unlink_err = 1;
        } else {
#endif
            data.unlink_err = 0;
#if NETDATASEL < 2
        }
#endif
        data.unlink_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &pid, &data, BPF_ANY);
    }

    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_fsync")
#else
SEC("kprobe/vfs_fsync")
#endif
int netdata_vfs_fsync(struct pt_regs* ctx)
{
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    struct netdata_vfs_stat_t data = { };
    struct netdata_vfs_stat_t *fill;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_FSYNC, 1);
    fill = bpf_map_lookup_elem(&tbl_vfs_pid ,&pid);
    if (fill) {
        netdata_update_u32(&fill->fsync_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_FSYNC, 1);
            netdata_update_u32(&fill->fsync_err, 1) ;
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_FSYNC, 1);
            data.fsync_err = 1;
        } else {
#endif
            data.fsync_err = 0;
#if NETDATASEL < 2
        }
#endif
        data.fsync_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &pid, &data, BPF_ANY);
    }

    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_open")
#else
SEC("kprobe/vfs_open")
#endif
int netdata_vfs_open(struct pt_regs* ctx)
{
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    struct netdata_vfs_stat_t data = { };
    struct netdata_vfs_stat_t *fill;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_OPEN, 1);
    fill = bpf_map_lookup_elem(&tbl_vfs_pid ,&pid);
    if (fill) {
        netdata_update_u32(&fill->open_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_OPEN, 1);
            netdata_update_u32(&fill->open_err, 1) ;
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_OPEN, 1);
            data.open_err = 1;
        } else {
#endif
            data.open_err = 0;
#if NETDATASEL < 2
        }
#endif
        data.open_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &pid, &data, BPF_ANY);
    }

    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/vfs_create")
#else
SEC("kprobe/vfs_create")
#endif
int netdata_vfs_create(struct pt_regs* ctx)
{
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    struct netdata_vfs_stat_t data = { };
    struct netdata_vfs_stat_t *fill;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_CREATE, 1);
    fill = bpf_map_lookup_elem(&tbl_vfs_pid ,&pid);
    if (fill) {
        netdata_update_u32(&fill->create_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_CREATE, 1);
            netdata_update_u32(&fill->create_err, 1) ;
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_CREATE, 1);
            data.create_err = 1;
        } else {
#endif
            data.create_err = 0;
#if NETDATASEL < 2
        }
#endif
        data.create_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &pid, &data, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

