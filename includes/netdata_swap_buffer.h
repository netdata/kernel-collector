// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_SWAP_BUFFER_H_
#define _NETDATA_SWAP_BUFFER_H_ 1

#define NETDATA_SWAP_RINGBUF_SIZE (1 << 20)

enum netdata_swap_event_action {
    NETDATA_SWAP_EVENT_READ  = 0,
    NETDATA_SWAP_EVENT_WRITE = 1,
};

struct netdata_swap_event_t {
    __u64 ct;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char  name[TASK_COMM_LEN];
    __u8  action;
    __u8  pad[3];
};

#endif /* _NETDATA_SWAP_BUFFER_H_ */
