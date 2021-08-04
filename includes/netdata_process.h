// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_EBPF_PROCESS_H_
#define _NETDATA_EBPF_PROCESS_H_ 1

#include <linux/sched.h>

struct netdata_pid_stat_t {
    __u64 pid_tgid;                     //Unique identifier
    __u32 pid;                          //process id

    //Counter
    __u32 exit_call;                    //Exit syscalls (exit for exit_group)
    __u32 release_call;                 //Exit syscalls (exit and exit_group)
    __u32 fork_call;                    //Start syscall (fork, clone, forkv)
    __u32 clone_call;                    //Start syscall (fork, clone, forkv)

    //Counter
    __u32 fork_err;
    __u32 clone_err;

    __u8 removeme;
};

enum process_counters {
    NETDATA_KEY_CALLS_DO_EXIT,

    NETDATA_KEY_CALLS_RELEASE_TASK,

    NETDATA_KEY_CALLS_DO_FORK,
    NETDATA_KEY_ERROR_DO_FORK,

    NETDATA_KEY_CALLS_SYS_CLONE,
    NETDATA_KEY_ERROR_SYS_CLONE,

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_GLOBAL_COUNTER
};

#endif /* _NETDATA_EBPF_PROCESS_H_ */

