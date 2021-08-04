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

/************************************************************************************
 *     
 *                                 MAPS Section
 *     
 ***********************************************************************************/

struct bpf_map_def SEC("maps") tbl_pid_stats = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct netdata_pid_stat_t),
    .max_entries = PID_MAX_DEFAULT
};

struct bpf_map_def SEC("maps") tbl_total_stats = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries =  NETDATA_GLOBAL_COUNTER
};

struct bpf_map_def SEC("maps") process_ctrl = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = NETDATA_CONTROLLER_END
};

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

/************************************************************************************
 *     
 *                                   PROCESS Section
 *     
 ***********************************************************************************/

SEC("kprobe/do_exit")
int netdata_sys_exit(struct pt_regs* ctx)
{
    struct netdata_pid_stat_t *fill;
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;

    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_DO_EXIT, 1);
    __u32 *apps = bpf_map_lookup_elem(&process_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&key);
    if (fill) {
        libnetdata_update_u32(&fill->exit_call, 1) ;
    } 

    return 0;
}

SEC("kprobe/release_task")
int netdata_release_task(struct pt_regs* ctx)
{
    struct netdata_pid_stat_t *fill;
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;

    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_RELEASE_TASK, 1);
    __u32 *apps = bpf_map_lookup_elem(&process_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&key);
    if (fill) {
        libnetdata_update_u32(&fill->release_call, 1) ;
        fill->removeme = 1;
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
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    struct netdata_pid_stat_t data = { };
    struct netdata_pid_stat_t *fill;

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

    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_DO_FORK, 1);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)) 
    if(threads) {
        libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_SYS_CLONE, 1);
    }
#endif
#if NETDATASEL < 2
    if (ret < 0) {
        libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_DO_FORK, 1);
# if (LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)) 
        if(threads) {
            libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_SYS_CLONE, 1);
        }
# endif
    } 
#endif

    __u32 *apps = bpf_map_lookup_elem(&process_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&key);
    if (fill) {
        fill->release_call = 0;
        libnetdata_update_u32(&fill->fork_call, 1) ;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)) 
        if(threads) {
            libnetdata_update_u32(&fill->clone_call, 1) ;
        }
#endif

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_u32(&fill->fork_err, 1) ;
# if (LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)) 
            if(threads) {
                libnetdata_update_u32(&fill->clone_err, 1) ;
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
            data.fork_err = 1;
# if (LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)) 
            if (threads) {
                data.clone_err = 1;
            }
# endif
        } 
#endif
        bpf_map_update_elem(&tbl_pid_stats, &key, &data, BPF_ANY);
    }

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
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u64 arg1 = (__u64)PT_REGS_PARM2(ctx);

    arg1 &= CLONE_THREAD|CLONE_VM;
    if(!arg1)
        return 0;

    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_SYS_CLONE, 1);
#if NETDATASEL < 2
    if (ret < 0) {
        libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_SYS_CLONE, 1);
    } 
#endif
    __u32 *apps = bpf_map_lookup_elem(&process_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&key);
    if (fill) {
        libnetdata_update_u32(&fill->clone_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_u32(&fill->clone_err, 1) ;
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  
        data.clone_call = 1;
#if NETDATASEL < 2
        if (ret < 0) {
            data.clone_err = 1;
        } 
#endif

        bpf_map_update_elem(&tbl_pid_stats, &key, &data, BPF_ANY);
    }

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
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;

    int threads = 0;
    struct kernel_clone_args *args = (struct kernel_clone_args *)PT_REGS_PARM1(ctx); 
    int exit_signal;
    bpf_probe_read(&exit_signal, sizeof(int), (void *)&args->exit_signal);
    // SIGCHLD is used by vfork/fork
    if (exit_signal != SIGCHLD) {
        threads = 1;
        libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_SYS_CLONE, 1);
    }

    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_DO_FORK, 1);
#if NETDATASEL < 2
    if (ret < 0) {
        libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_DO_FORK, 1);
        if(threads) {
            libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_SYS_CLONE, 1);
        }
    } 
#endif

    __u32 *apps = bpf_map_lookup_elem(&process_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&key);
    if (fill) {
        fill->release_call = 0;
        libnetdata_update_u32(&fill->fork_call, 1) ;

        if(threads) {
            libnetdata_update_u32(&fill->clone_call, 1) ;
        }

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_u32(&fill->fork_err, 1) ;
            if(threads) {
                libnetdata_update_u32(&fill->clone_err, 1) ;
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
            data.fork_err = 1;
            if (threads) {
                data.clone_err = 1;
            }
        }
#endif

        bpf_map_update_elem(&tbl_pid_stats, &key, &data, BPF_ANY);
    }
    return 0;
}

#endif

SEC("kprobe/try_to_wake_up")
int netdata_enter_try_to_wake_up(struct pt_regs* ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)(0x00000000FFFFFFFF & pid_tgid);
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

