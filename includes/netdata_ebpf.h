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

// Copied from linux/samples/bpf/tracex1_kern.c
#define _(P)                                                                   \
        ({                                                                     \
                typeof(P) val = 0;                                             \
                bpf_probe_read(&val, sizeof(val), &(P));                       \
                val;                                                           \
        })

// Copied from linux/samples/bpf/trace_common.h
#ifdef __x86_64__
#define NETDATA_SYSCALL(SYS) "__x64_sys_" __stringify(SYS)
#elif defined(__s390x__)
#define NETDATA_SYSCALL(SYS) "__s390x_" __stringify(SYS)
#else
#define NETDATA_SYSCALL(SYS) "sys_" __stringify(SYS)
#endif

#endif /* _NETDATA_EBPF_ */
