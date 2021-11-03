// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_CACHE_H_
#define _NETDATA_CACHE_H_ 1

typedef struct netdata_cachestat {
    __u64 add_to_page_cache_lru;
    __u64 mark_page_accessed;
    __u64 account_page_dirtied;
    __u64 mark_buffer_dirty;
} netdata_cachestat_t;

enum cachestat_counters {
    NETDATA_KEY_CALLS_ADD_TO_PAGE_CACHE_LRU,
    NETDATA_KEY_CALLS_MARK_PAGE_ACCESSED,
    NETDATA_KEY_CALLS_ACCOUNT_PAGE_DIRTIED,
    NETDATA_KEY_CALLS_MARK_BUFFER_DIRTY,

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_CACHESTAT_END
};

#endif /* _NETDATA_CACHE_H_ */
