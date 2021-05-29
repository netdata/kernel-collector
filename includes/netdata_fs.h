// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_FS_H_
#define _NETDATA_FS_H_ 1

typedef struct netdata_fs_hist {
    u32 hist_id;
    u32 bin;
} netdata_fs_hist_t;

enum fs_counters {
    NETDATA_KEY_CALLS_READ,
    NETDATA_KEY_CALLS_WRITE,
    NETDATA_KEY_CALLS_OPEN,
    NETDATA_KEY_CALLS_SYNC,

    NETDATA_FS_END
};

#define NETDATA_FS_MAX_BINS 32UL
#define NETDATA_FS_MAX_BINS_POS (NETDATA_FS_MAX_BINS - 1)
#define NETDATA_FS_HISTOGRAM_LENGTH  (NETDATA_FS_MAX_BINS * NETDATA_FS_MAX_BINS)


#endif /* _NETDATA_FS_H_ */

