#define KBUILD_MODNAME "process_kern"
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


struct bpf_map_def SEC("maps") tbl_pid_stats = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct netdata_pid_stat_t),
    .max_entries = 100000
};

struct bpf_map_def SEC("maps") tbl_total_stats = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)) 
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries =  NETDATA_GLOBAL_COUNTER
};


#if NETDATASEL == 1 && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0))
struct bpf_map_def SEC("maps") tbl_syscall_stats = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)) 
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1024
};
#endif


/************************************************************************************
 *     
 *                                 COMMON Section
 *     
 ***********************************************************************************/

static unsigned int log2(unsigned int v)
{
    unsigned int r;
    unsigned int shift;

    r = (v > 0xFFFF) << 4; v >>= r;
    shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
    shift = (v > 0xF) << 2; v >>= shift; r |= shift;
    shift = (v > 0x3) << 1; v >>= shift; r |= shift;
    r |= (v >> 1);

    return r;
}

static unsigned int log2l(unsigned long v)
{
    unsigned int hi = v >> 32;
    if (hi)
        return log2(hi) + 32;
    else
        return log2(v);
}

static void netdata_update_u32(u32 *res, u32 value) 
{
    if (!value)
        return;

    __sync_fetch_and_add(res, value);
    if ( (0xFFFFFFFFFFFFFFFF - *res) <= value) {
        *res = value;
    }
}

static void netdata_update_u64(__u64 *res, __u64 value) 
{
    if (!value)
        return;

    __sync_fetch_and_add(res, value);
    if ( (0xFFFFFFFFFFFFFFFF - *res) <= value) {
        *res = value;
    }
}

static void netdata_update_global(__u32 key, __u64 value)
{
    __u64 *res;
    res = bpf_map_lookup_elem(&tbl_total_stats, &key);
    if (res) {
        netdata_update_u64(res, value) ;
    } else
        bpf_map_update_elem(&tbl_total_stats, &key, &value, BPF_NOEXIST);
}

/*
static void netdata_reset_stat(struct netdata_pid_stat_t *ptr)
{
    ptr->open_call = 0;
    ptr->write_call = 0;
    ptr->writev_call = 0;
    ptr->read_call = 0;
    ptr->readv_call = 0;
    ptr->unlink_call = 0;
    ptr->exit_call = 0;
    ptr->fork_call = 0;
    ptr->close_call = 0;

    ptr->write_bytes = 0;
    ptr->writev_bytes = 0;
    ptr->read_bytes = 0;
    ptr->readv_bytes = 0;

    ptr->open_err = 0;
    ptr->write_err = 0;
    ptr->writev_err = 0;
    ptr->read_err = 0;
    ptr->readv_err = 0;
    ptr->unlink_err = 0;
    ptr->fork_err = 0;
}
**/

#if NETDATASEL == 1 && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0))
static inline void send_perf_error(struct pt_regs* ctx, int ret, int type, __u32 pid)
{
}
#endif

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
    struct netdata_pid_stat_t *fill;
    struct netdata_pid_stat_t data = { };
    __u64 tot;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);


    netdata_update_global(NETDATA_KEY_CALLS_VFS_WRITE, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->write_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(NETDATA_KEY_ERROR_VFS_WRITE, 1);
            netdata_update_u32(&fill->write_err, 1) ;
        } else {
#endif
            ret = (ssize_t)PT_REGS_PARM3(ctx);
            tot = log2l(ret);
            netdata_update_global(NETDATA_KEY_BYTES_VFS_WRITE, tot);
            netdata_update_u64(&fill->write_bytes, tot);
#if NETDATASEL < 2
        }
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(NETDATA_KEY_ERROR_VFS_WRITE, 1);
            data.write_err = 1;
        } else {
#endif
            ret = (ssize_t)PT_REGS_PARM3(ctx);
            tot = log2l(ret);
            netdata_update_global(NETDATA_KEY_BYTES_VFS_WRITE, tot);
            data.write_bytes = tot;
#if NETDATASEL < 2
        }
#endif
        data.write_call = 1;

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

#if NETDATASEL == 1 && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0))
    if (ret < 0) {
        send_perf_error(ctx,(int)ret, 4, pid);
    }
#endif

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
    struct netdata_pid_stat_t *fill;
    struct netdata_pid_stat_t data = { };
    __u64 tot;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    netdata_update_global(NETDATA_KEY_CALLS_VFS_WRITEV, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->writev_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(NETDATA_KEY_ERROR_VFS_WRITEV, 1);
            netdata_update_u32(&fill->writev_err, 1) ;
        } else {
#endif
            ret = (ssize_t)PT_REGS_PARM3(ctx);
            tot = log2l(ret);
            netdata_update_global(NETDATA_KEY_BYTES_VFS_WRITEV, tot);
            netdata_update_u64(&fill->writev_bytes, tot);
#if NETDATASEL < 2
        }
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(NETDATA_KEY_ERROR_VFS_WRITEV, 1);
            data.writev_err = 1;
        } else {
#endif
            ret = (ssize_t)PT_REGS_PARM3(ctx);
            tot = log2l(ret);
            netdata_update_global(NETDATA_KEY_BYTES_VFS_WRITEV, tot);
            data.writev_bytes = (unsigned long)tot;
#if NETDATASEL < 2
        }
#endif
        data.writev_call = 1;

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

#if NETDATASEL == 1 && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0))
    if (ret < 0) {
        send_perf_error(ctx,(int)ret, 4, pid);
    }
#endif

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
    struct netdata_pid_stat_t *fill;
    struct netdata_pid_stat_t data = { };
    __u64 tot;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    netdata_update_global(NETDATA_KEY_CALLS_VFS_READ, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->read_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(NETDATA_KEY_ERROR_VFS_READ, 1);
            netdata_update_u32(&fill->read_err, 1) ;
        } else {
#endif
            ret = (ssize_t)PT_REGS_PARM3(ctx);
            tot = log2l(ret);
            netdata_update_global(NETDATA_KEY_BYTES_VFS_READ, tot);
            netdata_update_u64(&fill->read_bytes, tot);
#if NETDATASEL < 2
        }
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(NETDATA_KEY_ERROR_VFS_READ, 1);
            data.read_err = 1;
        } else {
#endif
            ret = (ssize_t)PT_REGS_PARM3(ctx);
            tot = log2l(ret);
            netdata_update_global(NETDATA_KEY_BYTES_VFS_READ, tot);
            data.read_bytes = (unsigned long)tot;
#if NETDATASEL < 2
        }
#endif
        data.read_call = 1;

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

#if NETDATASEL == 1 && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0))
    if (ret < 0) {
        send_perf_error(ctx,(int)ret, 3, pid);
    }
#endif

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
    struct netdata_pid_stat_t *fill;
    struct netdata_pid_stat_t data = { };
    __u64 tot;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    netdata_update_global(NETDATA_KEY_CALLS_VFS_READV, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->readv_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(NETDATA_KEY_ERROR_VFS_READV, 1);
            netdata_update_u32(&fill->readv_err, 1) ;
        } else {
#endif
            ret = (ssize_t)PT_REGS_PARM3(ctx);
            tot = log2l(ret);
            netdata_update_global(NETDATA_KEY_BYTES_VFS_READV, tot);
            netdata_update_u64(&fill->readv_bytes, tot);
#if NETDATASEL < 2
        }
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(NETDATA_KEY_ERROR_VFS_READV, 1);
            data.readv_err = 1;
        } else {
#endif
            ret = (ssize_t)PT_REGS_PARM3(ctx);
            tot = log2l(ret);
            netdata_update_global(NETDATA_KEY_BYTES_VFS_READV, tot);
            data.readv_bytes = (unsigned long)tot;
#if NETDATASEL < 2
        }
#endif
        data.readv_call = 1;

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

#if NETDATASEL == 1 && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0))
    if (ret < 0) {
        send_perf_error(ctx,(int)ret, 3, pid);
    }
#endif

    return 0;
}

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(5,5,19))
#if NETDATASEL < 2
SEC("kretprobe/do_sys_open")
#else
SEC("kprobe/do_sys_open")
#endif
#else
#if NETDATASEL < 2
SEC("kretprobe/do_sys_openat2")
#else
SEC("kprobe/do_sys_openat2")
#endif // Endif NETDATASEL
#endif //ENDIF KERNEL VERSION
int netdata_sys_open(struct pt_regs* ctx)
{
#if NETDATASEL < 2
    int ret = (ssize_t)PT_REGS_RC(ctx);
#endif
    struct netdata_pid_stat_t *fill;
    struct netdata_pid_stat_t data = { };
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    netdata_update_global(NETDATA_KEY_CALLS_DO_SYS_OPEN, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->open_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(NETDATA_KEY_ERROR_DO_SYS_OPEN, 1);
            netdata_update_u32(&fill->open_err, 1) ;
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

#if NETDATASEL < 2
        if (ret < 0) {
            data.open_err = 1;
            netdata_update_global(NETDATA_KEY_ERROR_DO_SYS_OPEN, 1);
        } else {
#endif
            data.open_err = 0;
#if NETDATASEL < 2
        }
#endif
        data.open_call = 1;

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

#if NETDATASEL == 1 && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0))
    if (ret < 0) {
        send_perf_error(ctx,(int)ret, 0, pid);
    }
#endif

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
    struct netdata_pid_stat_t data = { };
    struct netdata_pid_stat_t *fill;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    netdata_update_global(NETDATA_KEY_CALLS_VFS_UNLINK, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->unlink_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(NETDATA_KEY_ERROR_VFS_UNLINK, 1);
            netdata_update_u32(&fill->unlink_err, 1) ;
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(NETDATA_KEY_ERROR_VFS_UNLINK, 1);
            data.unlink_err = 1;
        } else {
#endif
            data.unlink_err = 0;
#if NETDATASEL < 2
        }
#endif
        data.unlink_call = 1;

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

#if NETDATASEL == 1 && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0))
    if (ret < 0) {
        send_perf_error(ctx,(int)ret, 2, pid);
    }
#endif

    return 0;
}

/************************************************************************************
 *     
 *                                   PROCESS Section
 *     
 ***********************************************************************************/


SEC("kprobe/do_exit")
int netdata_sys_exit(struct pt_regs* ctx)
{
    struct netdata_pid_stat_t *fill;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    netdata_update_global(NETDATA_KEY_CALLS_DO_EXIT, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->exit_call, 1) ;
    } 

    return 0;
}

SEC("kprobe/release_task")
int netdata_release_task(struct pt_regs* ctx)
{
    struct netdata_pid_stat_t *fill;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    netdata_update_global(NETDATA_KEY_CALLS_RELEASE_TASK, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->release_call, 1) ;
        fill->removeme = 1;
        //netdata_reset_stat(fill);

        //bpf_map_delete_elem(&tbl_pid_stats, &pid);
    }

    return 0;
}

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(5,9,16))

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)) 
# if NETDATASEL < 2
SEC("kretprobe/_do_fork")
# else
SEC("kprobe/_do_fork")
# endif
#else 
# if NETDATASEL < 2
SEC("kretprobe/do_fork")
# else
SEC("kprobe/do_fork")
# endif
#endif
int netdata_fork(struct pt_regs* ctx)
{
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    struct netdata_pid_stat_t data = { };
    struct netdata_pid_stat_t *fill;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)) 
    int threads = 0;
    unsigned long clone_flags = PT_REGS_PARM1(ctx); 
    unsigned long flags;
    bpf_probe_read(&flags, sizeof(clone_flags), (void *)&clone_flags);
    if (flags & CLONE_VM) {
        threads = 1;
    } else {
        threads = 0;
    }
#endif

    netdata_update_global(NETDATA_KEY_CALLS_DO_FORK, 1);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)) 
    if(threads) {
        netdata_update_global(NETDATA_KEY_CALLS_SYS_CLONE, 1);
    }
#endif
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        fill->release_call = 0;
        netdata_update_u32(&fill->fork_call, 1) ;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)) 
        if(threads) {
            netdata_update_u32(&fill->clone_call, 1) ;
        }
#endif

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_u32(&fill->fork_err, 1) ;
            netdata_update_global(NETDATA_KEY_ERROR_DO_FORK, 1);
# if (LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)) 
            if(threads) {
                netdata_update_global(NETDATA_KEY_ERROR_SYS_CLONE, 1);
                netdata_update_u32(&fill->clone_err, 1) ;
            }
# endif
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  
        data.fork_call = 1;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)) 
        if(threads) {
            data.clone_call = 1;
        }
#endif
#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(NETDATA_KEY_ERROR_DO_FORK, 1);
            data.fork_err = 1;
# if (LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)) 
            if (threads) {
                netdata_update_global(NETDATA_KEY_ERROR_SYS_CLONE, 1);
                data.clone_err = 1;
            }
# endif
        } 
#endif
        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

#if NETDATASEL == 1
    if (ret < 0) {
# if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)) 
        send_perf_error(ctx,(int)ret, 7, pid);
# elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0))
        int sel = (threads)?8:7 ;
        send_perf_error(ctx,(int)ret, sel, pid);
# endif
    }
#endif

    return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)) 
#if NETDATASEL < 2
SEC("kretprobe/" NETDATA_SYSCALL(clone))
#else
SEC("kprobe/" NETDATA_SYSCALL(clone))
#endif
int netdata_clone(struct pt_regs* ctx)
{
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    struct netdata_pid_stat_t *fill;
    struct netdata_pid_stat_t data = { };
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    __u64 arg1 = (__u64)PT_REGS_PARM2(ctx);

    arg1 &= CLONE_THREAD|CLONE_VM;
    if(!arg1)
        return 0;

    netdata_update_global(NETDATA_KEY_CALLS_SYS_CLONE, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->clone_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(NETDATA_KEY_ERROR_SYS_CLONE, 1);
            netdata_update_u32(&fill->clone_err, 1) ;
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  
        data.clone_call = 1;
#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(NETDATA_KEY_ERROR_SYS_CLONE, 1);
            data.clone_err = 1;
        } 
#endif

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

#if NETDATASEL == 1 && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0))
    if (ret < 0) {
        send_perf_error(ctx,(int)ret, 8, pid);
    }
#endif

    return 0;
}
#endif



#else // End kernel <= 5.9.16

#if NETDATASEL < 2
// https://lore.kernel.org/patchwork/patch/1290639/
SEC("kretprobe/kernel_clone")
#else
SEC("kprobe/kernel_clone")
#endif
int netdata_sys_clone(struct pt_regs *ctx)
{
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    struct netdata_pid_stat_t data = { };
    struct netdata_pid_stat_t *fill;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    int threads = 0;
    struct kernel_clone_args *args = (struct kernel_clone_args *)PT_REGS_PARM1(ctx); 
    int exit_signal;
    bpf_probe_read(&exit_signal, sizeof(int), (void *)&args->exit_signal);
    // SIGCHLD is used by vfork/fork
    if (exit_signal != SIGCHLD) {
        threads = 1;
        netdata_update_global(NETDATA_KEY_CALLS_SYS_CLONE, 1);
    }

    netdata_update_global(NETDATA_KEY_CALLS_DO_FORK, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        fill->release_call = 0;
        netdata_update_u32(&fill->fork_call, 1) ;

        if(threads) {
            netdata_update_u32(&fill->clone_call, 1) ;
        }

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_u32(&fill->fork_err, 1) ;
            netdata_update_global(NETDATA_KEY_ERROR_DO_FORK, 1);
            if(threads) {
                netdata_update_global(NETDATA_KEY_ERROR_SYS_CLONE, 1);
                netdata_update_u32(&fill->clone_err, 1) ;
            }
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;
        data.pid = tgid;
        data.fork_call = 1;
        if(threads) {
            data.clone_call = 1;
        }
#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(NETDATA_KEY_ERROR_DO_FORK, 1);
            data.fork_err = 1;
            if (threads) {
                netdata_update_global(NETDATA_KEY_ERROR_SYS_CLONE, 1);
                data.clone_err = 1;
            }
        }
#endif

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }
    return 0;
}

#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)) 
#if NETDATASEL < 2
SEC("kretprobe/close_fd")
#else
SEC("kprobe/close_fd")
#endif
#else
#if NETDATASEL < 2
SEC("kretprobe/__close_fd")
#else
SEC("kprobe/__close_fd")
#endif
#endif
int netdata_close(struct pt_regs* ctx)
{
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    struct netdata_pid_stat_t data = { };
    struct netdata_pid_stat_t *fill;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    netdata_update_global(NETDATA_KEY_CALLS_CLOSE_FD, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->close_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(NETDATA_KEY_ERROR_CLOSE_FD, 1);
            netdata_update_u32(&fill->close_err, 1) ;
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  
        data.close_call = 1;
#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(NETDATA_KEY_ERROR_CLOSE_FD, 1);
            data.close_err = 1;
        } 
#endif

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

#if NETDATASEL == 1 && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0))
    if (ret < 0) {
        send_perf_error(ctx,(int)ret, 1, pid);
    }
#endif

    return 0;
}

SEC("kprobe/try_to_wake_up")
int netdata_enter_try_to_wake_up(struct pt_regs* ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    struct netdata_pid_stat_t *fill;
    struct netdata_pid_stat_t data = { };

    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (!fill) {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }


    return 0;
}

char _license[] SEC("license") = "GPL";
