#define KBUILD_MODNAME "shm_netdata"
#include <linux/bpf.h>

#include <linux/threads.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,4,14))
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#else
#include "netdata_bpf_helpers.h"
#endif
#include "netdata_ebpf.h"

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,4,14))
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
#else
struct bpf_map_def SEC("maps") tbl_shm = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_SHM_END
};

struct bpf_map_def SEC("maps") tbl_pid_shm = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u32),
    .value_size = sizeof(netdata_shm_t),
    .max_entries = PID_MAX_DEFAULT
};

struct bpf_map_def SEC("maps") shm_ctrl = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = NETDATA_CONTROLLER_END
};
#endif

SEC("kprobe/" NETDATA_SYSCALL(shmget))
int netdata_syscall_shmget(struct pt_regs *ctx)
{
    netdata_shm_t data = {};

    libnetdata_update_global(&tbl_shm, NETDATA_KEY_SHMGET_CALL, 1);

    // check if apps is enabled; if not, don't record apps data.
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&shm_ctrl, &key);
    if (apps) {
        if (*apps == 0) {
            return 0;
        }
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    netdata_shm_t *fill = bpf_map_lookup_elem(&tbl_pid_shm, &key);
    if (fill) {
        libnetdata_update_u64(&fill->get, 1);
    } else {
        data.get = 1;
        bpf_map_update_elem(&tbl_pid_shm, &key, &data, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/" NETDATA_SYSCALL(shmat))
int netdata_syscall_shmat(struct pt_regs *ctx)
{
    netdata_shm_t data = {};

    libnetdata_update_global(&tbl_shm, NETDATA_KEY_SHMAT_CALL, 1);

    // check if apps is enabled; if not, don't record apps data.
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&shm_ctrl, &key);
    if (apps) {
        if (*apps == 0) {
            return 0;
        }
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    netdata_shm_t *fill = bpf_map_lookup_elem(&tbl_pid_shm, &key);
    if (fill) {
        libnetdata_update_u64(&fill->at, 1);
    } else {
        data.at = 1;
        bpf_map_update_elem(&tbl_pid_shm, &key, &data, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/" NETDATA_SYSCALL(shmdt))
int netdata_syscall_shmdt(struct pt_regs *ctx)
{
    netdata_shm_t data = {};

    libnetdata_update_global(&tbl_shm, NETDATA_KEY_SHMDT_CALL, 1);

    // check if apps is enabled; if not, don't record apps data.
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&shm_ctrl, &key);
    if (apps) {
        if (*apps == 0) {
            return 0;
        }
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    netdata_shm_t *fill = bpf_map_lookup_elem(&tbl_pid_shm, &key);
    if (fill) {
        libnetdata_update_u64(&fill->dt, 1);
    } else {
        data.dt = 1;
        bpf_map_update_elem(&tbl_pid_shm, &key, &data, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/" NETDATA_SYSCALL(shmctl))
int netdata_syscall_shmctl(struct pt_regs *ctx)
{
    netdata_shm_t data = {};

    libnetdata_update_global(&tbl_shm, NETDATA_KEY_SHMCTL_CALL, 1);

    // check if apps is enabled; if not, don't record apps data.
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&shm_ctrl, &key);
    if (apps) {
        if (*apps == 0) {
            return 0;
        }
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    key = (__u32)(pid_tgid >> 32);
    netdata_shm_t *fill = bpf_map_lookup_elem(&tbl_pid_shm, &key);
    if (fill) {
        libnetdata_update_u64(&fill->ctl, 1);
    } else {
        data.ctl = 1;
        bpf_map_update_elem(&tbl_pid_shm, &key, &data, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
