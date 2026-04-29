// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_PROCESS_BUFFER_H_
#define _NETDATA_PROCESS_BUFFER_H_ 1

#define NETDATA_PROCESS_RINGBUF_SIZE (1 << 20)

enum netdata_process_event_action {
    NETDATA_PROCESS_EVENT_EXIT     = 0,
    NETDATA_PROCESS_EVENT_RELEASE  = 1,
    NETDATA_PROCESS_EVENT_EXEC     = 2,
    NETDATA_PROCESS_EVENT_FORK     = 3,
    NETDATA_PROCESS_EVENT_THREAD   = 4,
    NETDATA_PROCESS_EVENT_FORK_ERR = 5,
};

struct netdata_process_event_t {
    __u64 ct;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char  name[TASK_COMM_LEN];
    __u8  action;
    __u8  pad[3];
};

#endif /* _NETDATA_PROCESS_BUFFER_H_ */
