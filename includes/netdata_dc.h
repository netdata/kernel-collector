// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_DIRECTORY_CACHE_H_
#define _NETDATA_DIRECTORY_CACHE_H_ 1

typedef struct netdata_dc_stat {
    __u64 ct;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char name[TASK_COMM_LEN];

    __u32 references;
    __u32 slow;
    __u32 missed;
} netdata_dc_stat_t;

enum directory_cache_counters {
    NETDATA_KEY_DC_REFERENCE,
    NETDATA_KEY_DC_SLOW,
    NETDATA_KEY_DC_MISS,

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_DIRECTORY_CACHE_END
};

enum directory_cachec_functions {
    NETDATA_LOOKUP_FAST,
    NETDATA_D_LOOKUP,

    NETDATA_DC_COUNTER
};

#endif /* _NETDATA_DIRECTORY_CACHE_H_ */

