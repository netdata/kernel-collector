#ifndef _NETDATA_EBPF_PROCESS_
# define _NETDATA_EBPF_PROCESS_ 1
# include <linux/sched.h>

struct netdata_error_report_t {
    char comm[TASK_COMM_LEN];
    __u32 pid;

    int type;
    int err;
};


//fork() creates process
//
struct netdata_pid_stat_t {
    __u64 pid_tgid;                     //Unique identifier
    __u32 pid;                          //process id

    //Counter
    __u32 open_call;                    //open syscalls (open and openat)
    __u32 write_call;                   //Write syscalls (write and writev)
    __u32 writev_call;                   //Write syscalls (write and writev)
    __u32 read_call;                    //Read syscalls ( read and readv)
    __u32 readv_call;                    //Read syscalls ( read and readv)
    __u32 unlink_call;                  //Remove syscalls (unlink for while)
    __u32 exit_call;                    //Exit syscalls (exit for exit_group)
    __u32 release_call;                 //Exit syscalls (exit and exit_group)
    __u32 fork_call;                    //Start syscall (fork, clone, forkv)
    __u32 clone_call;                    //Start syscall (fork, clone, forkv)
    __u32 close_call;                   //Close syscall (close)

    //Accumulator
    __u64 write_bytes;
    __u64 writev_bytes;
    __u64 readv_bytes;
    __u64 read_bytes;

    //Counter
    __u32 open_err;
    __u32 write_err;
    __u32 writev_err;
    __u32 read_err;
    __u32 readv_err;
    __u32 unlink_err;
    __u32 fork_err;
    __u32 clone_err;
    __u32 close_err;

    __u8 removeme;
};

//ebpf_process.c
# define NETDATA_GLOBAL_COUNTER 24

# define NETDATA_KEY_CALLS_DO_SYS_OPEN 0
# define NETDATA_KEY_ERROR_DO_SYS_OPEN 1

# define NETDATA_KEY_CALLS_VFS_WRITE 2
# define NETDATA_KEY_ERROR_VFS_WRITE 3
# define NETDATA_KEY_BYTES_VFS_WRITE 4

# define NETDATA_KEY_CALLS_VFS_READ 5
# define NETDATA_KEY_ERROR_VFS_READ 6
# define NETDATA_KEY_BYTES_VFS_READ 7

# define NETDATA_KEY_CALLS_VFS_UNLINK 8
# define NETDATA_KEY_ERROR_VFS_UNLINK 9

# define NETDATA_KEY_CALLS_DO_EXIT 10

# define NETDATA_KEY_CALLS_RELEASE_TASK 11

# define NETDATA_KEY_CALLS_DO_FORK 12
# define NETDATA_KEY_ERROR_DO_FORK 13

# define NETDATA_KEY_CALLS_CLOSE_FD 14
# define NETDATA_KEY_ERROR_CLOSE_FD 15

# define NETDATA_KEY_CALLS_SYS_CLONE 16
# define NETDATA_KEY_ERROR_SYS_CLONE 17

# define NETDATA_KEY_CALLS_VFS_WRITEV 18
# define NETDATA_KEY_ERROR_VFS_WRITEV 19
# define NETDATA_KEY_BYTES_VFS_WRITEV 20

# define NETDATA_KEY_CALLS_VFS_READV 21
# define NETDATA_KEY_ERROR_VFS_READV 22
# define NETDATA_KEY_BYTES_VFS_READV 23

//network_viewer.c
# define NETDATA_SOCKET_COUNTER 14

# define NETDATA_KEY_CALLS_TCP_SENDMSG 0
# define NETDATA_KEY_ERROR_TCP_SENDMSG 1
# define NETDATA_KEY_BYTES_TCP_SENDMSG 2

# define NETDATA_KEY_CALLS_TCP_CLEANUP_RBUF 3
# define NETDATA_KEY_ERROR_TCP_CLEANUP_RBUF 4
# define NETDATA_KEY_BYTES_TCP_CLEANUP_RBUF 5

# define NETDATA_KEY_CALLS_TCP_CLOSE 6

# define NETDATA_KEY_CALLS_UDP_RECVMSG 7
# define NETDATA_KEY_ERROR_UDP_RECVMSG 8
# define NETDATA_KEY_BYTES_UDP_RECVMSG 9

# define NETDATA_KEY_CALLS_UDP_SENDMSG 10
# define NETDATA_KEY_ERROR_UDP_SENDMSG 11
# define NETDATA_KEY_BYTES_UDP_SENDMSG 12

# define NETDATA_KEY_TCP_RETRANSMIT 13

#endif
