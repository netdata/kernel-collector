// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_FD_BUFFER_H_
#define _NETDATA_FD_BUFFER_H_ 1

#define NETDATA_FD_RINGBUF_SIZE (1 << 20)

enum netdata_fd_event_action {
    NETDATA_FD_EVENT_OPEN  = 0,
    NETDATA_FD_EVENT_CLOSE = 1,
};

struct netdata_fd_event_t {
    __u64 ct;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char  name[TASK_COMM_LEN];
    __u8  action;
    __u8  error;
    __u8  pad[2];
};

#endif /* _NETDATA_FD_BUFFER_H_ */
