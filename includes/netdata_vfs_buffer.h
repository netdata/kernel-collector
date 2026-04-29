// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_VFS_BUFFER_H_
#define _NETDATA_VFS_BUFFER_H_ 1

#define NETDATA_VFS_RINGBUF_SIZE (1 << 20)

enum netdata_vfs_event_action {
    NETDATA_VFS_EVENT_WRITE  = 0,
    NETDATA_VFS_EVENT_WRITEV = 1,
    NETDATA_VFS_EVENT_READ   = 2,
    NETDATA_VFS_EVENT_READV  = 3,
    NETDATA_VFS_EVENT_UNLINK = 4,
    NETDATA_VFS_EVENT_FSYNC  = 5,
    NETDATA_VFS_EVENT_OPEN   = 6,
    NETDATA_VFS_EVENT_CREATE = 7,
};

struct netdata_vfs_event_t {
    __u64 ct;
    __u64 bytes;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char  name[TASK_COMM_LEN];
    __u8  action;
    __u8  error;
    __u8  pad[2];
};

#endif /* _NETDATA_VFS_BUFFER_H_ */
