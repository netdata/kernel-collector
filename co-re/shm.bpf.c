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

static inline int netdata_ebpf_common_shmget()
{
    int store_apps = netdata_global_apps_shm(NETDATA_KEY_SHMGET_CALL);
    if (!store_apps)
        return 0;

    return 0;
}

static inline int netdata_ebpf_common_shmat()
{
    int store_apps = netdata_global_apps_shm(NETDATA_KEY_SHMAT_CALL);
    if (!store_apps)
        return 0;

    return 0;
}

static inline int netdata_ebpf_common_shmdt()
{
    int store_apps = netdata_global_apps_shm(NETDATA_KEY_SHMDT_CALL);
    if (!store_apps)
        return 0;

    return 0;
}

static inline int netdata_ebpf_common_shmctl()
{
    int store_apps = netdata_global_apps_shm(NETDATA_KEY_SHMCTL_CALL);
    if (!store_apps)
        return 0;

    return 0;
}

/************************************************************************************
 *
 *                     SHARED MEMORY (tracepoint)
 *
 ***********************************************************************************/

SEC("tracepoint/syscalls/sys_enter_shmget")
int netdata_syscall_shmget(struct trace_event_raw_sys_enter *arg)
{
    return netdata_ebpf_common_shmget();
}

SEC("tracepoint/syscalls/sys_enter_shmat")
int netdata_syscall_shmat(struct trace_event_raw_sys_enter *arg)
{
    return netdata_ebpf_common_shmat();
}

SEC("tracepoint/syscalls/sys_enter_shmdt")
int netdata_syscall_shmdt(struct trace_event_raw_sys_enter *arg)
{
    return netdata_ebpf_common_shmdt();
}

SEC("tracepoint/syscalls/sys_enter_shmctl")
int netdata_syscall_shmctl(struct trace_event_raw_sys_enter *arg)
{
    return netdata_ebpf_common_shmctl();
}

/************************************************************************************
 *
 *                     SHARED MEMORY (kprobe)
 *
 ***********************************************************************************/

SEC("kprobe/netdata_shmget_probe")
int BPF_KPROBE(netdata_shmget_probe)
{
    return netdata_ebpf_common_shmget();
}

SEC("kprobe/netdata_shmat_probe")
int BPF_KPROBE(netdata_shmat_probe)
{
    return netdata_ebpf_common_shmat();
}

SEC("kprobe/netdata_shmdt_probe")
int BPF_KPROBE(netdata_shmdt_probe)
{
    return netdata_ebpf_common_shmdt();
}

SEC("kprobe/netdata_shmctl_probe")
int BPF_KPROBE(netdata_shmctl_probe)
{
    return netdata_ebpf_common_shmctl();
}

/************************************************************************************
 *
 *                     SHARED MEMORY (trampoline)
 *
 ***********************************************************************************/

SEC("fentry/netdata_shmget")
int BPF_PROG(netdata_shmget_fentry)
{
    return netdata_ebpf_common_shmget();
}

SEC("fentry/netdata_shmat")
int BPF_PROG(netdata_shmat_fentry)
{
    return netdata_ebpf_common_shmat();
}

SEC("fentry/netdata_shmdt")
int BPF_PROG(netdata_shmdt_fentry)
{
    return netdata_ebpf_common_shmdt();
}

SEC("fentry/netdata_shmctl")
int BPF_PROG(netdata_shmctl_fentry)
{
    return netdata_ebpf_common_shmctl();
}

char _license[] SEC("license") = "GPL";

