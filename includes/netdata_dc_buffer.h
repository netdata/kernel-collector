// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_DC_BUFFER_H_
#define _NETDATA_DC_BUFFER_H_ 1

#define NETDATA_DC_RINGBUF_SIZE (1 << 20)

enum netdata_dc_event_action {
    NETDATA_DC_EVENT_REFERENCE = 0,
    NETDATA_DC_EVENT_SLOW      = 1,
    NETDATA_DC_EVENT_SLOW_MISS = 2,
};

struct netdata_dc_event_t {
    __u64 ct;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char  name[TASK_COMM_LEN];
    __u8  action;
    __u8  pad[3];
};

#endif /* _NETDATA_DC_BUFFER_H_ */
