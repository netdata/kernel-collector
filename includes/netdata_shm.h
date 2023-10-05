// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_SHM_H_
#define _NETDATA_SHM_H_ 1

typedef struct netdata_shm {
    __u64 ct;
    __u32 tgid;
    char name[TASK_COMM_LEN];

    __u32 get;
    __u32 at;
    __u32 dt;
    __u32 ctl;
} netdata_shm_t;

enum shm_counters {
    NETDATA_KEY_SHMGET_CALL,
    NETDATA_KEY_SHMAT_CALL,
    NETDATA_KEY_SHMDT_CALL,
    NETDATA_KEY_SHMCTL_CALL,

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_SHM_END
};

#endif /* _NETDATA_SHM_H_ */
