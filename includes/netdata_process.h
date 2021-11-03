// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_EBPF_PROCESS_H_
#define _NETDATA_EBPF_PROCESS_H_ 1

// /sys/kernel/tracing/events/sched/sched_process_exit/format
typedef struct netdata_sched_process_exit {
    __u64 pad;      // This is not used with eBPF
    char comm[16] ; // offset:8;       size:16;        signed:1;
    int pid;        // offset:24;      size:4; signed:1;
    int prio;       // offset:28;      size:4; signed:1;
} netdata_sched_process_exit_t;

// /sys/kernel/tracing/events/sched/sched_process_fork/format
typedef struct netdata_sched_process_fork {
    __u64 pad;                // This is not used with eBPF
    char parent_comm[16];     // offset:8;       size:16;        signed:1;
    int parent_pid;           // offset:24;      size:4; signed:1;
    char child_comm[16];      // offset:28;      size:16;        signed:1;
    int child_pid;            // offset:44;      size:4; signed:1;
} netdata_sched_process_fork_t;

// /sys/kernel/tracing/events/sched/sched_process_exec/format
typedef struct netdata_sched_process_exec {
    __u64 pad;      // This is not used with eBPF
    int filename;   // offset:8;       size:4; signed:1;
    int pid;        // offset:12;      size:4; signed:1;
    int old_pid;   // offset:16;      size:4; signed:1;
} netdata_sched_process_exec_t;

struct netdata_pid_stat_t {
    __u64 pid_tgid;                     //Unique identifier
    __u32 pid;                          //process id

    //Counter
    __u32 exit_call;                    //Exit syscalls (exit for exit_group)
    __u32 release_call;                 //Exit syscalls (exit and exit_group)
    __u32 create_process;               //Start syscall (fork, clone, forkv)
    __u32 create_thread;                //Start syscall (fork, clone, forkv)

    __u32 task_err;

    __u8 removeme;
};

enum process_counters {
    NETDATA_KEY_CALLS_DO_EXIT,

    NETDATA_KEY_CALLS_RELEASE_TASK,

    NETDATA_KEY_CALLS_PROCESS,
    NETDATA_KEY_ERROR_PROCESS,

    NETDATA_KEY_CALLS_THREAD,
    NETDATA_KEY_ERROR_THREAD,

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_GLOBAL_COUNTER
};

#endif /* _NETDATA_EBPF_PROCESS_H_ */

