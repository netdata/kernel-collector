#define KBUILD_MODNAME "shm_netdata"

#include <linux/threads.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "netdata_ebpf.h"

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_SHM_END);
} tbl_shm  SEC(".maps");

struct {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    __uint(type, BPF_MAP_TYPE_HASH);
#else
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#endif
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
    .type = BPF_MAP_TYPE_HASH,
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

#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION >= 1)
SEC("ksyscall/shmget")
#else
SEC("kprobe/" NETDATA_SYSCALL(shmget))
#endif
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

    netdata_shm_t *fill = netdata_get_pid_structure(&key, &shm_ctrl, &tbl_pid_shm);
    if (fill) {
        libnetdata_update_u64(&fill->get, 1);
    } else {
        data.get = 1;
        bpf_map_update_elem(&tbl_pid_shm, &key, &data, BPF_ANY);
    }

    return 0;
}

#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION >= 1)
SEC("ksyscall/shmat")
#else
SEC("kprobe/" NETDATA_SYSCALL(shmat))
#endif
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

    netdata_shm_t *fill = netdata_get_pid_structure(&key, &shm_ctrl, &tbl_pid_shm);
    if (fill) {
        libnetdata_update_u64(&fill->at, 1);
    } else {
        data.at = 1;
        bpf_map_update_elem(&tbl_pid_shm, &key, &data, BPF_ANY);
    }

    return 0;
}

#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION >= 1)
SEC("ksyscall/shmdt")
#else
SEC("kprobe/" NETDATA_SYSCALL(shmdt))
#endif
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

    netdata_shm_t *fill = netdata_get_pid_structure(&key, &shm_ctrl, &tbl_pid_shm);
    if (fill) {
        libnetdata_update_u64(&fill->dt, 1);
    } else {
        data.dt = 1;
        bpf_map_update_elem(&tbl_pid_shm, &key, &data, BPF_ANY);
    }

    return 0;
}

#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION >= 1)
SEC("ksyscall/shmctl")
#else
SEC("kprobe/" NETDATA_SYSCALL(shmctl))
#endif
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

    netdata_shm_t *fill = netdata_get_pid_structure(&key, &shm_ctrl, &tbl_pid_shm);
    if (fill) {
        libnetdata_update_u64(&fill->ctl, 1);
    } else {
        data.ctl = 1;
        bpf_map_update_elem(&tbl_pid_shm, &key, &data, BPF_ANY);
    }

    return 0;
}

/**
 * Release task
 *
 * Removing a pid when it's no longer needed helps us reduce the default
 * size used with our tables.
 *
 * When a process stops so fast that apps.plugin or cgroup.plugin cannot detect it, we don't show
 * the information about the process, so it is safe to remove the information about the table.
 */
SEC("kprobe/release_task")
int netdata_release_task_shm(struct pt_regs* ctx)
{
    netdata_shm_t *removeme;
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&shm_ctrl ,&key);
    if (apps) {
        if (*apps == 0)
            return 0;
    } else
        return 0;

    removeme = netdata_get_pid_structure(&key, &shm_ctrl, &tbl_pid_shm);
    if (removeme) {
        bpf_map_delete_elem(&tbl_pid_shm, &key);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

