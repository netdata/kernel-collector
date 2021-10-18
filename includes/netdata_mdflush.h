// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_MDFLUSH_H_
#define _NETDATA_MDFLUSH_H_ 1

#include <linux/types.h>

typedef struct mdflush_key {
    dev_t unit;
} mdflush_key_t;

typedef struct mdflush_val {
    // incremental counter storing the total flushes so far.
    u64 cnt;
} mdflush_val_t;

#endif /* _NETDATA_MDFLUSH_H_ */
