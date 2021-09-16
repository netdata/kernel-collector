#define KBUILD_MODNAME "fd_kern"
#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/sched.h>
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,10,17))
# include <linux/sched/task.h>
#endif

#include <linux/threads.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,4,14))
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#else
#include "netdata_bpf_helpers.h"
#endif
#include "netdata_ebpf.h"

/************************************************************************************
 *     
 *                                 MAPS Section
 *     
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,4,14))
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct netdata_fd_stat_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} tbl_fd_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_FD_COUNTER);
} tbl_fd_global SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} fd_ctrl SEC(".maps");

#else

struct bpf_map_def SEC("maps") tbl_fd_pid = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct netdata_fd_stat_t),
    .max_entries = PID_MAX_DEFAULT
};

struct bpf_map_def SEC("maps") tbl_fd_global = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries =  NETDATA_FD_COUNTER
};

struct bpf_map_def SEC("maps") fd_ctrl = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = NETDATA_CONTROLLER_END
};

#endif

/************************************************************************************
 *     
 *                                   Probe Section
 *     
 ***********************************************************************************/

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
    struct netdata_fd_stat_t *fill;
    struct netdata_fd_stat_t data = { };
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;

    libnetdata_update_global(&tbl_fd_global, NETDATA_KEY_CALLS_DO_SYS_OPEN, 1);
#if NETDATASEL < 2
    if (ret < 0) {
        libnetdata_update_global(&tbl_fd_global, NETDATA_KEY_ERROR_DO_SYS_OPEN, 1);
    } 
#endif

    __u32 *apps = bpf_map_lookup_elem(&fd_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;


    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_fd_pid ,&key);
    if (fill) {
        libnetdata_update_u32(&fill->open_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_u32(&fill->open_err, 1) ;
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

#if NETDATASEL < 2
        if (ret < 0) {
            data.open_err = 1;
        } else {
#endif
            data.open_err = 0;
#if NETDATASEL < 2
        }
#endif
        data.open_call = 1;

        bpf_map_update_elem(&tbl_fd_pid, &key, &data, BPF_ANY);
    }

    return 0;
}

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
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    struct netdata_fd_stat_t data = { };
    struct netdata_fd_stat_t *fill;

    libnetdata_update_global(&tbl_fd_global, NETDATA_KEY_CALLS_CLOSE_FD, 1);
#if NETDATASEL < 2
    if (ret < 0) {
        libnetdata_update_global(&tbl_fd_global, NETDATA_KEY_ERROR_CLOSE_FD, 1);
    } 
#endif

    __u32 *apps = bpf_map_lookup_elem(&fd_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_fd_pid ,&key);
    if (fill) {
        libnetdata_update_u32(&fill->close_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_u32(&fill->close_err, 1) ;
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  
        data.close_call = 1;
#if NETDATASEL < 2
        if (ret < 0) {
            data.close_err = 1;
        } 
#endif

        bpf_map_update_elem(&tbl_fd_pid, &key, &data, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

