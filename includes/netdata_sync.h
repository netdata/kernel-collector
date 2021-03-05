// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_SYNC_H_
#define _NETDATA_SYNC_H_ 1

enum sync_counters {
    NETDATA_KEY_SYNC_CALL,
    NETDATA_KEY_SYNC_ERROR,

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_SYNC_END
};

#endif /* _NETDATA_SYNC_H_ */
