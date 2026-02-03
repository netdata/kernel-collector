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

NETDATA_BPF_PERCPU_ARRAY_DEF(tbl_shm, __u32, __u64, NETDATA_SHM_END);
NETDATA_BPF_HASH_DEF(tbl_pid_shm, __u32, netdata_shm_t, PID_MAX_DEFAULT);
NETDATA_BPF_ARRAY_DEF(shm_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

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
    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&shm_ctrl))
        return 0;

    netdata_shm_t *fill = netdata_get_pid_structure(&key, &tgid, &shm_ctrl, &tbl_pid_shm);
    if (fill) {
        libnetdata_update_u32(&fill->get, 1);
    } else {
        data.ct = bpf_ktime_get_ns();
        libnetdata_update_uid_gid(&data.uid, &data.gid);
        data.tgid = tgid;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif

        data.get = 1;
        bpf_map_update_elem(&tbl_pid_shm, &key, &data, BPF_ANY);

        libnetdata_update_global(&shm_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
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
    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&shm_ctrl))
        return 0;

    netdata_shm_t *fill = netdata_get_pid_structure(&key, &tgid, &shm_ctrl, &tbl_pid_shm);
    if (fill) {
        libnetdata_update_u32(&fill->at, 1);
    } else {
        data.ct = bpf_ktime_get_ns();
        libnetdata_update_uid_gid(&data.uid, &data.gid);
        data.tgid = tgid;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif

        data.at = 1;
        bpf_map_update_elem(&tbl_pid_shm, &key, &data, BPF_ANY);

        libnetdata_update_global(&shm_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
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
    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&shm_ctrl))
        return 0;

    netdata_shm_t *fill = netdata_get_pid_structure(&key, &tgid, &shm_ctrl, &tbl_pid_shm);
    if (fill) {
        libnetdata_update_u32(&fill->dt, 1);
    } else {
        data.ct = bpf_ktime_get_ns();
        libnetdata_update_uid_gid(&data.uid, &data.gid);
        data.tgid = tgid;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif

        data.dt = 1;
        bpf_map_update_elem(&tbl_pid_shm, &key, &data, BPF_ANY);

        libnetdata_update_global(&shm_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
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
    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&shm_ctrl))
        return 0;

    netdata_shm_t *fill = netdata_get_pid_structure(&key, &tgid, &shm_ctrl, &tbl_pid_shm);
    if (fill) {
        libnetdata_update_u32(&fill->ctl, 1);
    } else {
        data.ct = bpf_ktime_get_ns();
        libnetdata_update_uid_gid(&data.uid, &data.gid);
        data.tgid = tgid;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif

        data.ctl = 1;
        bpf_map_update_elem(&tbl_pid_shm, &key, &data, BPF_ANY);

        libnetdata_update_global(&shm_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

