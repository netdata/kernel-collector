// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_EBPF_
#define _NETDATA_EBPF_ 1

#include <linux/sched.h>

#include "netdata_cache.h"
#include "netdata_network.h"
#include "netdata_process.h"

struct netdata_error_report_t {
    char comm[TASK_COMM_LEN];
    __u32 pid;

    int type;
    int err;
};

#endif /* _NETDATA_EBPF_PROCESS_ */
