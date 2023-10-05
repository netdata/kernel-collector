// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_CACHE_H_
#define _NETDATA_CACHE_H_ 1

typedef struct netdata_cachestat {
    __u64 ct;
    __u32 tgid;
    char name[TASK_COMM_LEN];

    __s64 total;
    __s64 misses;
    __u64 dirty;
} netdata_cachestat_t;

enum cachestat_counters {
    NETDATA_KEY_TOTAL,
    NETDATA_KEY_MISSES,
    NETDATA_KEY_DIRTY,

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_CACHESTAT_END
};

#endif /* _NETDATA_CACHE_H_ */
