// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_SHM_BUFFER_H_
#define _NETDATA_SHM_BUFFER_H_ 1

#define NETDATA_SHM_RINGBUF_SIZE (1 << 20)

enum netdata_shm_event_action {
    NETDATA_SHM_EVENT_GET = 0,
    NETDATA_SHM_EVENT_AT  = 1,
    NETDATA_SHM_EVENT_DT  = 2,
    NETDATA_SHM_EVENT_CTL = 3,
};

struct netdata_shm_event_t {
    __u64 ct;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char  name[TASK_COMM_LEN];
    __u8  action;
    __u8  pad[3];
};

#endif /* _NETDATA_SHM_BUFFER_H_ */
