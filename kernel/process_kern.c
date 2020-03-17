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
    .value_size = sizeof(__u32),
    .max_entries =  NETDATA_GLOBAL_COUNTER
};


#if NETDATASEL == 1
struct bpf_map_def SEC("maps") tbl_syscall_stats = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
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
    if ( (0xFFFFFFFF - *res) <= value)
        *res = value;
    else 
        *res += value;
}

static void netdata_update_u64(u64 *res, u64 value) 
{
    if ( (0xFFFFFFFFFFFFFFFF - *res) <= value)
        *res = value;
    else 
        *res += value;
}

static void netdata_update_global(__u32 key, __u32 value)
{
    u32 *res;
    res = bpf_map_lookup_elem(&tbl_total_stats, &key);
    if (res) {
        netdata_update_u32(res, value) ;
    } else
        bpf_map_update_elem(&tbl_total_stats, &key, &value, BPF_NOEXIST);
}

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

#if NETDATASEL == 1
static inline void send_perf_error(struct pt_regs* ctx, int ret, int type, __u32 pid)
{
    struct netdata_error_report_t ner;

    bpf_get_current_comm(&ner.comm, sizeof(ner.comm));
    ner.pid = pid;
    ner.type = 4;
    int err = (int)ret;
    bpf_probe_read(&ner.err,  sizeof(ner.err), &err);

    pid = (__u32)bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &tbl_syscall_stats, pid, &ner, sizeof(ner));
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
#if NETDATASEL < 2
    ssize_t ret = (ssize_t)PT_REGS_RC(ctx);
#endif
    struct netdata_pid_stat_t *fill;
    struct netdata_pid_stat_t data = { };
    __u32 tot;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    netdata_update_global(2, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->write_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(3, 1);
            netdata_update_u32(&fill->write_err, 1) ;
        } else {
            tot = (__u32)log2l(ret);
#else
            tot = 0;
#endif
            netdata_update_global(4, tot);
            netdata_update_u64(&fill->write_bytes, (u64) tot);
#if NETDATASEL < 2
        }
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = pid;  

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(3, 1);
            data.write_err = 1;
        } else {
            tot = (__u32)log2l(ret);
#else
            tot = 0;
#endif
            netdata_update_global(4, tot);
            data.write_bytes = (u64)tot;
#if NETDATASEL < 2
        }
#endif
        data.write_call = 1;

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

#if NETDATASEL == 1
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
#if NETDATASEL < 2
    ssize_t ret = (ssize_t)PT_REGS_RC(ctx);
#endif
    struct netdata_pid_stat_t *fill;
    struct netdata_pid_stat_t data = { };
    __u32 tot;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    netdata_update_global(18, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->writev_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(19, 1);
            netdata_update_u32(&fill->writev_err, 1) ;
        } else {
            tot = (__u32)log2l(ret);
#else
            tot = 0;
#endif
            netdata_update_global(20, tot);
            netdata_update_u64(&fill->writev_bytes, (u64) tot);
#if NETDATASEL < 2
        }
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = pid;  

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(19, 1);
            data.writev_err = 1;
        } else {
            tot = (__u32)log2l(ret);
#else
            tot = 0;
#endif
            netdata_update_global(20, tot);
            data.writev_bytes = (unsigned long)tot;
#if NETDATASEL < 2
        }
#endif
        data.writev_call = 1;

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

#if NETDATASEL == 1
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
#if NETDATASEL < 2
    ssize_t ret = (ssize_t)PT_REGS_RC(ctx);
#endif
    struct netdata_pid_stat_t *fill;
    struct netdata_pid_stat_t data = { };
    __u32 tot;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    netdata_update_global(5, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->read_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(6, 1);
            netdata_update_u32(&fill->read_err, 1) ;
        } else {
            tot = (__u32)log2l(ret);
#else
            tot = 0;
#endif
            netdata_update_global(7, tot);
            netdata_update_u64(&fill->read_bytes, (u64) tot);
#if NETDATASEL < 2
        }
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = pid;  

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(6, 1);
            data.read_err = 1;
        } else {
            tot = (__u32)log2l(ret);
#else
            tot = 0;
#endif
            netdata_update_global(7, tot);
            data.read_bytes = (unsigned long)tot;
#if NETDATASEL < 2
        }
#endif
        data.read_call = 1;

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

#if NETDATASEL == 1
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
#if NETDATASEL < 2
    ssize_t ret = (ssize_t)PT_REGS_RC(ctx);
#endif
    struct netdata_pid_stat_t *fill;
    struct netdata_pid_stat_t data = { };
    __u32 tot;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    netdata_update_global(21, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->readv_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(22, 1);
            netdata_update_u32(&fill->readv_err, 1) ;
        } else {
            tot = (__u32)log2l(ret);
#else
            tot = 0;
#endif
            netdata_update_global(23, tot);
            netdata_update_u64(&fill->readv_bytes, (u64) tot);
#if NETDATASEL < 2
        }
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = pid;  

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(22, 1);
            data.readv_err = 1;
        } else {
            tot = (__u32)log2l(ret);
#else
            tot = 0;
#endif
            netdata_update_global(23, tot);
            data.readv_bytes = (unsigned long)tot;
#if NETDATASEL < 2
        }
#endif
        data.readv_call = 1;

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

#if NETDATASEL == 1
    if (ret < 0) {
        send_perf_error(ctx,(int)ret, 3, pid);
    }
#endif

    return 0;
}

#if NETDATASEL < 2
SEC("kretprobe/do_sys_open")
#else
SEC("kprobe/do_sys_open")
#endif
int netdata_sys_open(struct pt_regs* ctx)
{
#if NETDATASEL < 2
    int ret = (ssize_t)PT_REGS_RC(ctx);
#endif
    struct netdata_pid_stat_t *fill;
    struct netdata_pid_stat_t data = { };
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    netdata_update_global(0, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->open_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(1, 1);
            netdata_update_u32(&fill->open_err, 1) ;
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = pid;  

#if NETDATASEL < 2
        if (ret < 0) {
            data.open_err = 1;
            netdata_update_global(1, 1);
        } else {
#endif
            data.open_err = 0;
#if NETDATASEL < 2
        }
#endif
        data.open_call = 1;

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

#if NETDATASEL == 1
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

    netdata_update_global(8, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->unlink_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(9, 1);
            netdata_update_u32(&fill->unlink_err, 1) ;
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = pid;  

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(9, 1);
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

#if NETDATASEL == 1
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

    netdata_update_global(10, 1);
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

    netdata_update_global(11, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->release_call, 1) ;
        netdata_reset_stat(fill);
    }

    return 0;
}

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

    netdata_update_global(12, 1);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)) 
    if(threads) {
        netdata_update_global(16, 1);
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
            netdata_update_global(13, 1);
# if (LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)) 
            if(threads) {
                netdata_update_global(17, 1);
                netdata_update_u32(&fill->clone_err, 1) ;
            }
# endif
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = pid;  
        data.fork_call = 1;
#if NETDATASEL < 2
# if (LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)) 
        if(threads) {
            data.clone_call = 1;
        }
# endif
        if (ret < 0) {
            netdata_update_global(13, 1);
            data.fork_err = 1;
# if (LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)) 
            if (threads) {
                netdata_update_global(17, 1);
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
# else
        int sel = (threads)?8:7 ;
        send_perf_error(ctx,(int)ret, sel, pid);
# endif
    }
#endif

    return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)) 
# if defined(CONFIG_X86_64) 
#  if NETDATASEL < 2
SEC("kretprobe/__x64_sys_clone")
#  else
SEC("kprobe/__x64_sys_clone")
#  endif
# else
#  if NETDATASEL < 2
SEC("kretprobe/sys_clone")
#  else
SEC("kprobe/sys_clone")
#  endif
# endif
int netdata_clone(struct pt_regs* ctx)
{
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    struct netdata_pid_stat_t *fill;
    struct netdata_pid_stat_t data = { };
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    u64 arg1 = (u64)PT_REGS_PARM2(ctx);

    arg1 &= CLONE_THREAD|CLONE_VM;
    if(!arg1)
        return 0;

    netdata_update_global(16, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->clone_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(17, 1);
            netdata_update_u32(&fill->clone_err, 1) ;
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = pid;  
        data.clone_call = 1;
#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(17, 1);
            data.clone_err = 1;
        } 
#endif

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

#if NETDATASEL == 1
    if (ret < 0) {
        send_perf_error(ctx,(int)ret, 8, pid);
    }
#endif

    return 0;
}
#endif

#if NETDATASEL < 2
SEC("kretprobe/__close_fd")
#else
SEC("kprobe/__close_fd")
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

    netdata_update_global(14, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->close_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(15, 1);
            netdata_update_u32(&fill->close_err, 1) ;
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = pid;  
        data.close_call = 1;
#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_global(15, 1);
            data.close_err = 1;
        } 
#endif

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

#if NETDATASEL == 1
    if (ret < 0) {
        send_perf_error(ctx,(int)ret, 1, pid);
    }
#endif

    return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
