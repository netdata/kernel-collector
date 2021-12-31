#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "netdata_core.h"
#include "netdata_vfs.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct netdata_vfs_stat_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} tbl_vfs_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_VFS_COUNTER);
} tbl_vfs_stats  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} vfs_ctrl SEC(".maps");

/************************************************************************************
 *     
 *                               VFS Common
 *     
 ***********************************************************************************/

static __always_inline int netdata_common_vfs_write(__u64 tot, ssize_t ret)
{
    struct netdata_vfs_stat_t *fill;
    struct netdata_vfs_stat_t data = { };

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_WRITE, 1);

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_WRITE, tot);

    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&vfs_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_vfs_pid ,&key);
    if (fill) {
        libnetdata_update_u32(&fill->write_call, 1) ;

        if (ret < 0) {
            libnetdata_update_u32(&fill->write_err, 1) ;
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_WRITE, 1);
        } else
            libnetdata_update_u64(&fill->write_bytes, tot);

    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

        if (ret < 0)
            data.write_err = 1;
        else
            data.write_bytes = tot;

        data.write_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);
    }

    return 0;
}

static __always_inline int netdata_common_vfs_writev(__u64 tot, ssize_t ret)
{
    struct netdata_vfs_stat_t *fill;
    struct netdata_vfs_stat_t data = { };

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_WRITEV, 1);

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_WRITEV, tot);

    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&vfs_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_vfs_pid ,&key);
    if (fill) {
        libnetdata_update_u32(&fill->writev_call, 1) ;

        if (ret < 0) {
            libnetdata_update_u32(&fill->writev_err, 1) ;
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_WRITEV, 1);
        } else {
            libnetdata_update_u64(&fill->writev_bytes, tot);
        }
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

        if (ret < 0) {
            data.writev_err = 1;
        } else {
            data.writev_bytes = (unsigned long)tot;
        }
        data.writev_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);
    }

    return 0;
}

static __always_inline int netdata_common_vfs_read(__u64 tot, ssize_t ret)
{
    struct netdata_vfs_stat_t *fill;
    struct netdata_vfs_stat_t data = { };

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_READ, 1);
    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_READ, tot);

    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&vfs_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_vfs_pid ,&key);
    if (fill) {
        libnetdata_update_u32(&fill->read_call, 1) ;

        if (ret < 0) {
            libnetdata_update_u32(&fill->read_err, 1) ;
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_READ, 1);
        } else {
            libnetdata_update_u64(&fill->read_bytes, tot);
        }
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

        if (ret < 0) {
            data.read_err = 1;
        } else {
            data.read_bytes = (unsigned long)tot;
        }
        data.read_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);
    }

    return 0;
}

static __always_inline int netdata_common_vfs_readv(__u64 tot, ssize_t ret)
{
    struct netdata_vfs_stat_t *fill;
    struct netdata_vfs_stat_t data = { };

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_READV, 1);
    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_BYTES_VFS_READV, tot);

    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&vfs_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_vfs_pid ,&key);
    if (fill) {
        libnetdata_update_u32(&fill->readv_call, 1) ;

        if (ret < 0) {
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_READV, 1);
            libnetdata_update_u32(&fill->readv_err, 1) ;
        } else {
            libnetdata_update_u64(&fill->readv_bytes, tot);
        }
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

        if (ret < 0) {
            data.readv_err = 1;
        } else {
            data.readv_bytes = (unsigned long)tot;
        }
        data.readv_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);
    }

    return 0;
}

static __always_inline int netdata_common_vfs_unlink(int ret)
{
    struct netdata_vfs_stat_t data = { };
    struct netdata_vfs_stat_t *fill;

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_UNLINK, 1);

    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&vfs_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_vfs_pid ,&key);
    if (fill) {
        libnetdata_update_u32(&fill->unlink_call, 1) ;

        if (ret < 0) {
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_UNLINK, 1);
            libnetdata_update_u32(&fill->unlink_err, 1) ;
        }
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

        if (ret < 0)
            data.unlink_err = 1;
        else 
            data.unlink_err = 0;
        data.unlink_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);
    }

    return 0;
}

static __always_inline int netdata_common_vfs_fsync(int ret)
{
    struct netdata_vfs_stat_t data = { };
    struct netdata_vfs_stat_t *fill;

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_FSYNC, 1);

    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&vfs_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_vfs_pid ,&key);
    if (fill) {
        libnetdata_update_u32(&fill->fsync_call, 1) ;

        if (ret < 0) {
            libnetdata_update_u32(&fill->fsync_err, 1) ;
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_FSYNC, 1);
        } 
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

        if (ret < 0) {
            data.fsync_err = 1;
        } else {
            data.fsync_err = 0;
        }
        data.fsync_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);
    }

    return 0;
}

static __always_inline int netdata_common_vfs_open(int ret)
{
    struct netdata_vfs_stat_t data = { };
    struct netdata_vfs_stat_t *fill;

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_OPEN, 1);
    
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&vfs_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_vfs_pid ,&key);
    if (fill) {
        libnetdata_update_u32(&fill->open_call, 1) ;

        if (ret < 0) {
            libnetdata_update_u32(&fill->open_err, 1) ;
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_OPEN, 1);
        } 
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

        if (ret < 0) {
            data.open_err = 1;
        } else {
            data.open_err = 0;
        }
        data.open_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);
    }

    return 0;
}

static __always_inline int netdata_common_vfs_create(int ret)
{
    struct netdata_vfs_stat_t data = { };
    struct netdata_vfs_stat_t *fill;

    libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_CALLS_VFS_CREATE, 1);

    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&vfs_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_vfs_pid ,&key);
    if (fill) {
        libnetdata_update_u32(&fill->create_call, 1) ;

        if (ret < 0) {
            libnetdata_update_u32(&fill->create_err, 1) ;
            libnetdata_update_global(&tbl_vfs_stats, NETDATA_KEY_ERROR_VFS_CREATE, 1);
        } 
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

        if (ret < 0) {
            data.create_err = 1;
        } else {
            data.create_err = 0;
        }
        data.create_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);
    }

    return 0;
}

/************************************************************************************
 *     
 *                            VFS Section (kprobe)
 *     
 ***********************************************************************************/

SEC("kprobe/vfs_write")
int BPF_KPROBE(netdata_vfs_write_kprobe)
{
    ssize_t ret = (ssize_t)PT_REGS_PARM3(ctx);
    __u64 tot = libnetdata_log2l(ret);

    return netdata_common_vfs_write(tot, 0);
}

SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(netdata_vfs_write_kretprobe)
{
    ssize_t ret = (ssize_t)PT_REGS_PARM3(ctx);
    __u64 tot = libnetdata_log2l(ret);

    ret = (ssize_t)PT_REGS_RC(ctx);

    return netdata_common_vfs_write(tot, ret);
}

SEC("kprobe/vfs_writev")
int BPF_KPROBE(netdata_vfs_writev_kprobe)
{
    ssize_t ret = (ssize_t)PT_REGS_PARM3(ctx);
    __u64 tot = libnetdata_log2l(ret);

    return netdata_common_vfs_writev(tot, 0);
}

SEC("kretprobe/vfs_writev")
int BPF_KRETPROBE(netdata_vfs_writev_kretprobe)
{
    ssize_t ret = (ssize_t)PT_REGS_PARM3(ctx);
    __u64 tot = libnetdata_log2l(ret);

    ret = (ssize_t)PT_REGS_RC(ctx);

    return netdata_common_vfs_writev(tot, ret);
}

SEC("kprobe/vfs_read")
int BPF_KPROBE(netdata_vfs_read_kprobe)
{
    ssize_t ret = (ssize_t)PT_REGS_PARM3(ctx);
    __u64 tot = libnetdata_log2l(ret);

    return netdata_common_vfs_read(tot, 0);
}

SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(netdata_vfs_read_kretprobe)
{
    ssize_t ret = (ssize_t)PT_REGS_PARM3(ctx);
    __u64 tot = libnetdata_log2l(ret);

    ret = (ssize_t)PT_REGS_RC(ctx);

    return netdata_common_vfs_read(tot, ret);
}

SEC("kprobe/vfs_readv")
int BPF_KPROBE(netdata_vfs_readv_kprobe)
{
    ssize_t ret = (ssize_t)PT_REGS_PARM3(ctx);
    __u64 tot = libnetdata_log2l(ret);

    return netdata_common_vfs_readv(tot, 0);
}

SEC("kretprobe/vfs_readv")
int BPF_KRETPROBE(netdata_vfs_readv_kretprobe)
{
    ssize_t ret = (ssize_t)PT_REGS_PARM3(ctx);
    __u64 tot = libnetdata_log2l(ret);

    ret = (ssize_t)PT_REGS_RC(ctx);

    return netdata_common_vfs_readv(tot, ret);
}

SEC("kprobe/vfs_unlink")
int BPF_KPROBE(netdata_vfs_unlink_kprobe)
{
    return netdata_common_vfs_unlink(0);
}

SEC("kretprobe/vfs_unlink")
int BPF_KRETPROBE(netdata_vfs_unlink_kretprobe)
{
    int ret = (int)PT_REGS_RC(ctx);

    return netdata_common_vfs_unlink(ret);
}

SEC("kprobe/vfs_fsync")
int BPF_KPROBE(netdata_vfs_fsync_kprobe)
{
    return netdata_common_vfs_fsync(0);
}

SEC("kretprobe/vfs_fsync")
int BPF_KRETPROBE(netdata_vfs_fsync_kretprobe)
{
    int ret = (int)PT_REGS_RC(ctx);

    return netdata_common_vfs_fsync(ret);
}

SEC("kprobe/vfs_open")
int BPF_KPROBE(netdata_vfs_open_kprobe)
{
    return netdata_common_vfs_open(0);
}

SEC("kretprobe/vfs_open")
int BPF_KRETPROBE(netdata_vfs_open_kretprobe)
{
    int ret = (int)PT_REGS_RC(ctx);

    return netdata_common_vfs_open(ret);
}

SEC("kprobe/vfs_create")
int BPF_KPROBE(netdata_vfs_create_kprobe)
{
    return netdata_common_vfs_create(0);
}

SEC("kretprobe/vfs_create")
int BPF_KRETPROBE(netdata_vfs_create_kretprobe)
{
    int ret = (int)PT_REGS_RC(ctx);

    return netdata_common_vfs_create(ret);
}

/************************************************************************************
 *     
 *                            VFS Section (trampoline)
 *     
 ***********************************************************************************/

SEC("fentry/vfs_write")
int BPF_PROG(netdata_vfs_write_fentry, struct file *file, const char *buf, size_t count, loff_t *pos)
{
    __u64 tot = libnetdata_log2l((ssize_t)count);

    return netdata_common_vfs_write(tot, 0);
}

SEC("fexit/vfs_write")
int BPF_PROG(netdata_vfs_write_fexit, struct file *file, const char *buf, size_t count, loff_t *pos, ssize_t ret)
{
    __u64 tot;
    if (ret > 0)
        tot = libnetdata_log2l(ret);
    else
        tot = 0;

    return netdata_common_vfs_write(tot, ret);
}

SEC("fentry/vfs_writev")
int BPF_PROG(netdata_vfs_writev_fentry, struct file *file, const char *buf, size_t count, loff_t *pos)
{
    __u64 tot = libnetdata_log2l((ssize_t)count);

    return netdata_common_vfs_writev(tot, 0);
}

SEC("fexit/vfs_writev")
int BPF_PROG(netdata_vfs_writev_fexit, struct file *file, const char *buf, size_t count, loff_t *pos, ssize_t ret)
{
    __u64 tot;
    if (ret > 0)
        tot = libnetdata_log2l(ret);
    else
        tot = 0;

    return netdata_common_vfs_writev(tot, ret);
}

SEC("fentry/vfs_read")
int BPF_PROG(netdata_vfs_read_fentry, struct file *file, const char *buf, size_t count, loff_t *pos)
{
    __u64 tot = libnetdata_log2l((ssize_t)count);

    return netdata_common_vfs_read(tot, 0);
}

SEC("fexit/vfs_read")
int BPF_PROG(netdata_vfs_read_fexit, struct file *file, const char *buf, size_t count, loff_t *pos, ssize_t ret)
{
    __u64 tot;
    if (ret > 0)
        tot = libnetdata_log2l(ret);
    else
        tot = 0;

    return netdata_common_vfs_read(tot, ret);
}

SEC("fentry/vfs_readv")
int BPF_PROG(netdata_vfs_readv_fentry, struct file *file, const struct iovec *vec, unsigned long vlen, loff_t *pos, rwf_t flags)
{
    __u64 tot = libnetdata_log2l((ssize_t) vlen);

    return netdata_common_vfs_readv(tot, 0);
}

SEC("fexit/vfs_readv")
int BPF_PROG(netdata_vfs_readv_fexit, struct file *file, const struct iovec *vec, unsigned long vlen, loff_t *pos, rwf_t flags,
             ssize_t ret)
{
    __u64 tot;
    if (ret > 0)
        tot = libnetdata_log2l(ret);
    else
        tot = 0;

    return netdata_common_vfs_readv(tot, ret);
}

SEC("fentry/vfs_unlink")
int BPF_PROG(netdata_vfs_unlink_fentry)
{
    return netdata_common_vfs_unlink(0);
}

/*
SEC("fexit/vfs_unlink")
// KERNEL NEWER THAN 5.11.22
int BPF_PROG(netdata_vfs_unlink_fexit, struct user_namespace *mnt_userns, struct inode *dir, struct dentry *dentry,
             struct inode **delegated_inode, int ret)
// KERNEL OLDER THAN 5.12.0             
int BPF_PROG(netdata_vfs_unlink_fexit,struct inode *dir, struct dentry *dentry, struct inode **delegated_inode, int ret)
{
    return netdata_common_vfs_unlink(ret);
}
*/

SEC("fentry/vfs_fsync")
int BPF_PROG(netdata_vfs_fsync_fentry)
{
    return netdata_common_vfs_fsync(0);
}

SEC("fexit/vfs_fsync")
int BPF_PROG(netdata_vfs_fsync_fexit, struct file *file, int datasync, int ret)
{
    return netdata_common_vfs_fsync(ret);
}

SEC("fentry/vfs_open")
int BPF_PROG(netdata_vfs_open_fentry)
{
    return netdata_common_vfs_open(0);
}

SEC("fexit/vfs_open")
int BPF_PROG(netdata_vfs_open_fexit, const struct path *path, struct file *file, int ret)
{
    return netdata_common_vfs_open(ret);
}

SEC("fentry/vfs_create")
int BPF_PROG(netdata_vfs_create_fentry)
{
    return netdata_common_vfs_create(0);
}

/*
SEC("fexit/vfs_create")
// KERNEL NEWER THAN 5.11.22
int BPF_PROG(netdata_vfs_create_fexit, struct user_namespace *mnt_userns, struct inode *dir,
             struct dentry *dentry, umode_t mode, bool want_excl, int ret)
// KERNEL OLDER THAN 5.12.0             
int BPF_PROG(netdata_vfs_create_fexit, struct inode *dir, struct dentry *dentry, umode_t mode,
	     bool want_excl, int ret)
{
    return netdata_common_vfs_create(ret);
}
*/

char _license[] SEC("license") = "GPL";

