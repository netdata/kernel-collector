// SPDX-License-Identifier: GPL-3.0-or-later

#include <linux/sched.h>

#ifndef _NETDATA_OOMKILL_H_
#define _NETDATA_OOMKILL_H_ 1

typedef struct netdata_oomkill {
    // how many times a process was killed.
    u32 killcnt;

    // command of the process as obtained from the kernel's task_struct for the
    // OOM killed process.
    char comm[TASK_COMM_LEN];
} netdata_oomkill_t;

#endif /* _NETDATA_OOMKILL_H_ */
