#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "netdata_core.h"
#include "netdata_shm.h"

/************************************************************************************
 *
 *                                 MAPS
 *
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_SHM_END);
} tbl_shm  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, netdata_shm_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} tbl_pid_shm SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} shm_ctrl SEC(".maps");

/************************************************************************************
 *
 *                     SHARED MEMORY (common)
 *
 ***********************************************************************************/

static inline int netdata_global_apps_shm(__u32 idx)
{
    libnetdata_update_global(&tbl_shm, idx, 1);

    // check if apps is enabled; if not, don't record apps data.
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&shm_ctrl, &key);
    if (apps) {
        if (*apps == 0) {
            return 0;
        }
    }

    return 1;
}

/************************************************************************************
 *
 *                     SHARED MEMORY (tracepoint)
 *
 ***********************************************************************************/

SEC("tracepoint/syscalls/sys_enter_shmget")
int netdata_syscall_shmget(struct trace_event_raw_sys_enter *arg)
{
    int store_apps = netdata_global_apps_shm(NETDATA_KEY_SHMGET_CALL);
    if (!store_apps)
        return 0;

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmat")
int netdata_syscall_shmat(struct trace_event_raw_sys_enter *arg)
{
    int store_apps = netdata_global_apps_shm(NETDATA_KEY_SHMAT_CALL);
    if (!store_apps)
        return 0;

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmdt")
int netdata_syscall_shmdt(struct trace_event_raw_sys_enter *arg)
{
    int store_apps = netdata_global_apps_shm(NETDATA_KEY_SHMDT_CALL);
    if (!store_apps)
        return 0;

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmctl")
int netdata_syscall_shmctl(struct trace_event_raw_sys_enter *arg)
{
    int store_apps = netdata_global_apps_shm(NETDATA_KEY_SHMCTL_CALL);
    if (!store_apps)
        return 0;

    return 0;
}

/************************************************************************************
 *
 *                     SHARED MEMORY (kprobe)
 *
 ***********************************************************************************/

SEC("kprobe/netdata_shmget_probe")
int BPF_KPROBE(netdata_shmget_probe)
{
    int store_apps = netdata_global_apps_shm(NETDATA_KEY_SHMGET_CALL);
    if (!store_apps)
        return 0;

    return 0;
}

SEC("kprobe/netdata_shmat_probe")
int BPF_KPROBE(netdata_shmat_probe)
{
    int store_apps = netdata_global_apps_shm(NETDATA_KEY_SHMAT_CALL);
    if (!store_apps)
        return 0;

    return 0;
}

SEC("kprobe/netdata_shmdt_probe")
int BPF_KPROBE(netdata_shmdt_probe)
{
    int store_apps = netdata_global_apps_shm(NETDATA_KEY_SHMDT_CALL);
    if (!store_apps)
        return 0;

    return 0;
}

SEC("kprobe/netdata_shmctl_probe")
int BPF_KPROBE(netdata_shmctl_probe)
{
    int store_apps = netdata_global_apps_shm(NETDATA_KEY_SHMCTL_CALL);
    if (!store_apps)
        return 0;

    return 0;
}

char _license[] SEC("license") = "GPL";

