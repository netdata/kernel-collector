// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_FS_H_
#define _NETDATA_FS_H_ 1

enum fs_counters {
    NETDATA_KEY_CALLS_READ,
    NETDATA_KEY_CALLS_WRITE,
    NETDATA_KEY_CALLS_OPEN,
    NETDATA_KEY_CALLS_SYNC,

    NETDATA_FS_END
};

// We are using 24 as hard limit to avoid intervals bigger than
// 8 seconds and to keep memory aligment.
#define NETDATA_FS_MAX_BINS 24UL
#define NETDATA_FS_MAX_TABLES 4UL
#define NETDATA_FS_MAX_ELEMENTS (NETDATA_FS_MAX_BINS * NETDATA_FS_MAX_TABLES)
#define NETDATA_FS_MAX_BINS_POS (NETDATA_FS_MAX_BINS - 1)
#define NETDATA_FS_HISTOGRAM_LENGTH  (NETDATA_FS_MAX_BINS * NETDATA_FS_MAX_BINS)


#endif /* _NETDATA_FS_H_ */

