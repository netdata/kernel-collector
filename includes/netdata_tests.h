// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_TESTS_H_
#define _NETDATA_TESTS_H_ 1

#include <sys/resource.h>

static inline int netdata_ebf_memlock_limit(void)
{
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        return -1;
    }

    return 0;
}

#endif /* _NETDATA_TESTS_H_ */

