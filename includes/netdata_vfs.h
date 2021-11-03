// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_VFS_H_
#define _NETDATA_VFS_H_ 1

struct netdata_vfs_stat_t {
    __u64 pid_tgid;                     
    __u32 pid;                          
    __u32 pad;                          

    //Counter
    __u32 write_call;                   
    __u32 writev_call;                   
    __u32 read_call;                    
    __u32 readv_call;                   
    __u32 unlink_call;                  
    __u32 fsync_call;                  
    __u32 open_call;                  
    __u32 create_call;                  

    //Accumulator
    __u64 write_bytes;
    __u64 writev_bytes;
    __u64 readv_bytes;
    __u64 read_bytes;

    //Counter
    __u32 write_err;
    __u32 writev_err;
    __u32 read_err;
    __u32 readv_err;
    __u32 unlink_err;
    __u32 fsync_err;
    __u32 open_err;
    __u32 create_err;
};

enum vfs_counters {
    NETDATA_KEY_CALLS_VFS_WRITE,
    NETDATA_KEY_ERROR_VFS_WRITE,
    NETDATA_KEY_BYTES_VFS_WRITE,

    NETDATA_KEY_CALLS_VFS_WRITEV,
    NETDATA_KEY_ERROR_VFS_WRITEV,
    NETDATA_KEY_BYTES_VFS_WRITEV,

    NETDATA_KEY_CALLS_VFS_READ,
    NETDATA_KEY_ERROR_VFS_READ,
    NETDATA_KEY_BYTES_VFS_READ,

    NETDATA_KEY_CALLS_VFS_READV,
    NETDATA_KEY_ERROR_VFS_READV,
    NETDATA_KEY_BYTES_VFS_READV,

    NETDATA_KEY_CALLS_VFS_UNLINK,
    NETDATA_KEY_ERROR_VFS_UNLINK,

    NETDATA_KEY_CALLS_VFS_FSYNC,
    NETDATA_KEY_ERROR_VFS_FSYNC,

    NETDATA_KEY_CALLS_VFS_OPEN,
    NETDATA_KEY_ERROR_VFS_OPEN,

    NETDATA_KEY_CALLS_VFS_CREATE,
    NETDATA_KEY_ERROR_VFS_CREATE,

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_VFS_COUNTER
};

#endif /* _NETDATA_VFS_H_ */

