// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_EBPF_
#define _NETDATA_EBPF_ 1

#include <linux/sched.h>

#include "netdata_cache.h"
#include "netdata_network.h"
#include "netdata_process.h"
#include "netdata_sync.h"

struct netdata_error_report_t {
    char comm[TASK_COMM_LEN];
    __u32 pid;

    int type;
    int err;
};

// Use __always_inline instead inline to keep compatiblity with old kernels
// https://docs.cilium.io/en/v1.8/bpf/
// The condition to test kernel was added, because __always_inline broke the epbf.plugin
// on CentOS 7 and Ubuntu 18.04 (kernel 4.18)
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,19,0)) 
static __always_inline void libnetdata_update_u64(__u64 *res, __u64 value)
#else
static inline void libnetdata_update_u64(__u64 *res, __u64 value)
#endif
{
    __sync_fetch_and_add(res, value);
    if ( (0xFFFFFFFFFFFFFFFF - *res) <= value) {
        *res = value;
    }
}

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
