// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_SWAP_H_
#define _NETDATA_SWAP_H_ 1

typedef struct netdata_swap_access {
    __u64 ct;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char name[TASK_COMM_LEN];

    __u32 read;
    __u32 write;
} netdata_swap_access_t;

enum swap_counters {
    NETDATA_KEY_SWAP_READPAGE_CALL,
    NETDATA_KEY_SWAP_WRITEPAGE_CALL,

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_SWAP_END
};

#endif /* _NETDATA_SWAP_H_ */
