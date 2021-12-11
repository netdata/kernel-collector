#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "netdata_core.h"
#include "netdata_fd.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

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

/************************************************************************************
 *
 *                           COMMON SECTION(kprobe)
 *
 ***********************************************************************************/

static inline int netdata_are_apps_enabled()
{
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&fd_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    return 1;
}

static inline int netdata_apps_do_sys_openat2(long ret)
{
    struct netdata_fd_stat_t *fill;
    struct netdata_fd_stat_t data = { };

    if (!netdata_are_apps_enabled())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_fd_pid ,&key);
    if (fill) {
        libnetdata_update_u32(&fill->open_call, 1) ;
        if (ret < 0) 
            libnetdata_update_u32(&fill->open_err, 1) ;
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  
        if (ret < 0)
            data.open_err = 1;

    }

    data.open_call = 1;

    bpf_map_update_elem(&tbl_fd_pid, &key, &data, BPF_ANY);

    return 0;
}

static inline void netdata_sys_open_global(long ret)
{
    if (ret < 0)
        libnetdata_update_global(&tbl_fd_global, NETDATA_KEY_ERROR_DO_SYS_OPEN, 1);

    libnetdata_update_global(&tbl_fd_global, NETDATA_KEY_CALLS_DO_SYS_OPEN, 1);
}

static inline int netdata_apps_close_fd(int ret)
{
    struct netdata_fd_stat_t data = { };
    struct netdata_fd_stat_t *fill;

    if (!netdata_are_apps_enabled())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 key = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    fill = bpf_map_lookup_elem(&tbl_fd_pid ,&key);
    if (fill) {
        libnetdata_update_u32(&fill->close_call, 1) ;

    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  
        data.close_call = 1;
        if (ret < 0)
            data.close_err = 1;

        bpf_map_update_elem(&tbl_fd_pid, &key, &data, BPF_ANY);
    }

    return 0;
}

static inline void netdata_close_global(int ret)
{
    if (ret < 0)
        libnetdata_update_global(&tbl_fd_global, NETDATA_KEY_ERROR_CLOSE_FD, 1);

    libnetdata_update_global(&tbl_fd_global, NETDATA_KEY_CALLS_CLOSE_FD, 1);
}

/************************************************************************************
 *
 *                           FD SECTION(kprobe)
 *
 ***********************************************************************************/

SEC("kretprobe/do_sys_openat2")
int BPF_KRETPROBE(netdata_sys_open_kretprobe)
{
    long ret = (long)PT_REGS_RC(ctx);
    netdata_sys_open_global(ret);

    return netdata_apps_do_sys_openat2(ret);
}

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(netdata_sys_open_kprobe)
{
    netdata_sys_open_global(0);

    return netdata_apps_do_sys_openat2(0);
}

SEC("kretprobe/close_fd")
int BPF_KRETPROBE(netdata_close_fd_kretprobe)
{
    int ret = (ssize_t)PT_REGS_RC(ctx);
    netdata_close_global(ret);

    return netdata_apps_close_fd(ret);
}

SEC("kprobe/close_fd")
int BPF_KPROBE(netdata_close_fd_kprobe)
{
    netdata_close_global(0);

    return netdata_apps_close_fd(0);
}

SEC("kretprobe/__close_fd")
int BPF_KRETPROBE(netdata___close_fd_kretprobe)
{
    int ret = (ssize_t)PT_REGS_RC(ctx);
    netdata_close_global(ret);

    return netdata_apps_close_fd(ret);
}

SEC("kprobe/__close_fd")
int BPF_KPROBE(netdata___close_fd_kprobe)
{
    netdata_close_global(0);

    return netdata_apps_close_fd(0);
}

/************************************************************************************
 *
 *                           FD SECTION(trampoline)
 *
 ***********************************************************************************/

SEC("fexit/do_sys_openat2")
int BPF_PROG(netdata_sys_open_fexit, int dfd, const char *filename, struct open_how *how, long ret)
{
    netdata_sys_open_global(ret);

    return netdata_apps_do_sys_openat2(ret);
}

SEC("fentry/do_sys_openat2")
int BPF_PROG(netdata_sys_open_fentry)
{
    netdata_sys_open_global(0);

    return netdata_apps_do_sys_openat2(0);
}

SEC("fentry/close_fd")
int BPF_PROG(netdata_close_fd_fentry)
{
    netdata_close_global(0);

    return netdata_apps_close_fd(0);
}

SEC("fexit/close_fd")
int BPF_PROG(netdata_close_fd_fexit, unsigned fd, int ret)
{
    netdata_close_global(ret);

    return netdata_apps_close_fd(ret);
}

SEC("fentry/__close_fd")
int BPF_PROG(netdata___close_fd_fentry)
{
    netdata_close_global(0);

    return netdata_apps_close_fd(0);
}

SEC("fexit/__close_fd")
int BPF_PROG(netdata___close_fd_fexit, struct files_struct *files, unsigned fd, int ret)
{
    netdata_close_global(ret);

    return netdata_apps_close_fd(ret);
}

char _license[] SEC("license") = "GPL";

