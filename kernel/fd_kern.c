#define KBUILD_MODNAME "fd_kern"
#include <linux/version.h>
#include <linux/sched.h>
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,10,17))
# include <linux/sched/task.h>
#endif

#include <linux/threads.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "netdata_ebpf.h"

/************************************************************************************
 *     
 *                                 MAPS Section
 *     
 ***********************************************************************************/

NETDATA_BPF_HASH_DEF(tbl_fd_pid, __u32, struct netdata_fd_stat_t, PID_MAX_DEFAULT);
NETDATA_BPF_PERCPU_ARRAY_DEF(tbl_fd_global, __u32, __u64, NETDATA_FD_COUNTER);
NETDATA_BPF_ARRAY_DEF(fd_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

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

    libnetdata_update_global(&tbl_fd_global, NETDATA_KEY_CALLS_DO_SYS_OPEN, 1);
#if NETDATASEL < 2
    if (ret < 0) {
        libnetdata_update_global(&tbl_fd_global, NETDATA_KEY_ERROR_DO_SYS_OPEN, 1);
    } 
#endif

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&fd_ctrl))
        return 0;

    fill = netdata_get_pid_structure(&key, &tgid, &fd_ctrl, &tbl_fd_pid);
    if (fill) {
        libnetdata_update_u32(&fill->open_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_u32(&fill->open_err, 1) ;
        } 
#endif
    } else {
        data.ct = bpf_ktime_get_ns();
        libnetdata_update_uid_gid(&data.uid, &data.gid);
        data.tgid = tgid;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif

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

        libnetdata_update_global(&fd_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)) 
# if NETDATASEL < 2
SEC("kretprobe/close_fd")
# else
SEC("kprobe/close_fd")
# endif /* NETDATASEL < 2 */
#else /* KERNEL > 5.11 */
# if NETDATASEL < 2
#  if defined(RHEL_MAJOR) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)) && (LINUX_VERSION_CODE <= KERNEL_VERSION(4,19,0))
SEC("kretprobe/close_fd")
#  else /* RHEL_MAJOR */
SEC("kretprobe/__close_fd")
#  endif /* RHEL_MAJOR */
# else /* NETDATASEL < 2 */
#  if defined(RHEL_MAJOR) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)) && (LINUX_VERSION_CODE <= KERNEL_VERSION(4,19,0))
SEC("kprobe/close_fd")
#  else /* RHEL_MAJOR */
SEC("kprobe/__close_fd")
#  endif /* RHEL_MAJOR */
# endif /* NETDATASEL < 2 */
#endif /* KERNEL > 5.11 */
int netdata_close(struct pt_regs* ctx)
{
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    struct netdata_fd_stat_t data = { };
    struct netdata_fd_stat_t *fill;

    libnetdata_update_global(&tbl_fd_global, NETDATA_KEY_CALLS_CLOSE_FD, 1);
#if NETDATASEL < 2
    if (ret < 0) {
        libnetdata_update_global(&tbl_fd_global, NETDATA_KEY_ERROR_CLOSE_FD, 1);
    } 
#endif

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&fd_ctrl))
        return 0;

    fill = netdata_get_pid_structure(&key, &tgid, &fd_ctrl, &tbl_fd_pid);
    if (fill) {
        libnetdata_update_u32(&fill->close_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_u32(&fill->close_err, 1) ;
        } 
#endif
    } else {
        data.ct = bpf_ktime_get_ns();
        libnetdata_update_uid_gid(&data.uid, &data.gid);
        data.tgid = tgid;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif

        data.close_call = 1;
#if NETDATASEL < 2
        if (ret < 0) {
            data.close_err = 1;
        } 
#endif

        bpf_map_update_elem(&tbl_fd_pid, &key, &data, BPF_ANY);

        libnetdata_update_global(&fd_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

