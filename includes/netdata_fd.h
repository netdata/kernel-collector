// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_EBPF_FD_H_
#define _NETDATA_EBPF_FD_H_ 1

struct netdata_fd_stat_t {
    //Counter
    __u32 open_call;                    //open syscalls (open and openat)
    __u32 close_call;                   //Close syscall (close)

    //Counter
    __u32 open_err;
    __u32 close_err;
};

enum fd_counters {
    NETDATA_KEY_CALLS_DO_SYS_OPEN,
    NETDATA_KEY_ERROR_DO_SYS_OPEN,

    NETDATA_KEY_CALLS_CLOSE_FD,
    NETDATA_KEY_ERROR_CLOSE_FD,

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_FD_COUNTER
};

enum fd_actions {
    NETDATA_FD_OPEN,
    NETDATA_FD_CLOSE,

    NETDATA_FD_ACTIONS
};

#endif /* _NETDATA_EBPF_FD_H_ */

