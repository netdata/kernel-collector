// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_CACHE_BUFFER_H_
#define _NETDATA_CACHE_BUFFER_H_ 1

#define NETDATA_CACHESTAT_RINGBUF_SIZE (1 << 20)

enum netdata_cachestat_event_action {
    NETDATA_CACHESTAT_EVENT_PAGE_CACHE_LRU = 0,
    NETDATA_CACHESTAT_EVENT_PAGE_ACCESSED  = 1,
    NETDATA_CACHESTAT_EVENT_PAGE_DIRTIED   = 2,
    NETDATA_CACHESTAT_EVENT_BUFFER_DIRTY   = 3,
};

struct netdata_cachestat_event_t {
    __u64 ct;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char  name[TASK_COMM_LEN];
    __u8  action;
    __u8  pad[3];
};

#endif /* _NETDATA_CACHE_BUFFER_H_ */
