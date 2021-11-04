// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_DIRECTORY_CACHE_H_
#define _NETDATA_DIRECTORY_CACHE_H_ 1

typedef struct netdata_dc_stat {
    __u64 references;
    __u64 slow;
    __u64 missed;
} netdata_dc_stat_t;

enum directory_cache_counters {
    NETDATA_KEY_DC_REFERENCE,
    NETDATA_KEY_DC_SLOW,
    NETDATA_KEY_DC_MISS,

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_DIRECTORY_CACHE_END
};

#endif /* _NETDATA_DIRECTORY_CACHE_H_ */

