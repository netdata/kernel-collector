#ifndef NETDATA_LEGACY_TESTER
#define NETDATA_LEGACY_TESTER 1

#include <libbpf.h>
#include <bpf.h>

#include "../includes/netdata_defs.h"

#define VERSION_STRING_LEN 256
#define NETDATA_EBPF_PROGRAM_LEN  VERSION_STRING_LEN


/**
 * The RedHat magic number was got doing:
 *
 * 1797 = 7*256 + 5
 *
 *  For more details, please, read /usr/include/linux/version.h
 *  in any Red Hat installation.
 */
#define NETDATA_MINIMUM_RH_VERSION 1797

/**
 * 2048 = 8*256 + 0
 */
#define NETDATA_RH_8 2048

/**
 *  Kernel Version
 *
 *  Kernel versions are calculated using the following formula:
 *
 *  VERSION = LINUX_VERSION_MAJOR*65536 + LINUX_VERSION_PATCHLEVEL*256 + LINUX_VERSION_SUBLEVEL
 *
 *  Where LINUX_VERSION_MAJOR, LINUX_VERSION_PATCHLEVEL, and LINUX_VERSION_SUBLEVEL are extracted
 *  from /usr/include/linux/version.h.
 *
 *  LINUX_VERSION_SUBLEVEL has the maximum value 255, but linux can have more SUBLEVELS.
 *
 */
enum netdata_ebpf_kernel_versions {
    NETDATA_EBPF_KERNEL_4_11 = 264960,  //  264960 = 4 * 65536 + 15 * 256
    NETDATA_EBPF_KERNEL_4_14 = 265728,  //  264960 = 4 * 65536 + 14 * 256
    NETDATA_EBPF_KERNEL_4_15 = 265984,  //  265984 = 4 * 65536 + 15 * 256
    NETDATA_EBPF_KERNEL_4_17 = 266496,  //  266496 = 4 * 65536 + 17 * 256
    NETDATA_EBPF_KERNEL_5_0  = 327680,  //  327680 = 5 * 65536 +  0 * 256
    NETDATA_EBPF_KERNEL_5_10 = 330240,  //  330240 = 5 * 65536 + 10 * 256
    NETDATA_EBPF_KERNEL_5_11 = 330496,  //  330240 = 5 * 65536 + 11 * 256
    NETDATA_EBPF_KERNEL_5_14 = 331264,  //  331264 = 5 * 65536 + 14 * 256
    NETDATA_EBPF_KERNEL_5_15 = 331520,  //  331520 = 5 * 65536 + 15 * 256
    NETDATA_EBPF_KERNEL_5_16 = 331776   //  331776 = 5 * 65536 + 16 * 256
};

/**
 * Minimum value has relationship with libbpf support.
 */
#define NETDATA_MINIMUM_EBPF_KERNEL NETDATA_EBPF_KERNEL_4_11


enum netdata_kernel_flag {
    NETDATA_V3_10 = 1 << 0,
    NETDATA_V4_14 = 1 << 1,
    NETDATA_V4_16 = 1 << 2,
    NETDATA_V4_18 = 1 << 3,
    NETDATA_V5_4  = 1 << 4,
    NETDATA_V5_10 = 1 << 5,
    NETDATA_V5_11 = 1 << 6,
    NETDATA_V5_14 = 1 << 7,
    NETDATA_V5_15 = 1 << 8,
    NETDATA_V5_16 = 1 << 9
};

enum netdata_kernel_counter {
    NETDATA_3_10,
    NETDATA_4_14,
    NETDATA_4_16,
    NETDATA_4_18,
    NETDATA_5_4,
    NETDATA_5_10,
    NETDATA_5_11,
    NETDATA_5_14,
    NETDATA_5_15,
    NETDATA_5_16,

    NETDATA_VERSION_END
};

enum netdata_thread_flag {
    NETDATA_FLAG_BTRFS = 1 << 0,
    NETDATA_FLAG_CACHESTAT = 1 << 1,
    NETDATA_FLAG_DC = 1 << 2,
    NETDATA_FLAG_DISK = 1 << 3,
    NETDATA_FLAG_EXT4 = 1 << 4,
    NETDATA_FLAG_FD = 1 << 5,
    NETDATA_FLAG_SYNC = 1 << 6,
    NETDATA_FLAG_HARDIRQ = 1 << 7,
    NETDATA_FLAG_MDFLUSH = 1 << 8,
    NETDATA_FLAG_MOUNT = 1 << 9,
    NETDATA_FLAG_OOMKILL = 1 << 10,
    NETDATA_FLAG_PROCESS = 1 << 11,
    NETDATA_FLAG_SHM = 1 << 12,
    NETDATA_FLAG_SOCKET = 1 << 13,
    NETDATA_FLAG_SOFTIRQ = 1 << 14,
    NETDATA_FLAG_SWAP = 1 << 15,
    NETDATA_FLAG_VFS = 1 << 16,
    NETDATA_FLAG_NFS = 1 << 17,
    NETDATA_FLAG_XFS = 1 << 18,
    NETDATA_FLAG_ZFS = 1 << 19,
    NETDATA_FLAG_LOAD_BINARY = 1 << 20,
    NETDATA_FLAG_CONTENT = 1 << 21,

    NETDATA_FLAG_FS =  (uint64_t)(NETDATA_FLAG_BTRFS | NETDATA_FLAG_EXT4 | NETDATA_FLAG_VFS | NETDATA_FLAG_NFS | NETDATA_FLAG_XFS | NETDATA_FLAG_ZFS),
    NETDATA_FLAG_ALL = 0XFFFFFFFFFFFFFFFF
};

enum netdata_thread_OPT {
    NETDATA_OPT_BTRFS,
    NETDATA_OPT_CACHESTAT,
    NETDATA_OPT_DC,
    NETDATA_OPT_DISK,
    NETDATA_OPT_EXT4,
    NETDATA_OPT_FD,
    NETDATA_OPT_SYNC,
    NETDATA_OPT_HARDIRQ,
    NETDATA_OPT_MDFLUSH,
    NETDATA_OPT_MOUNT,
    NETDATA_OPT_OOMKILL,
    NETDATA_OPT_PROCESS,
    NETDATA_OPT_SHM,
    NETDATA_OPT_SOCKET,
    NETDATA_OPT_SOFTIRQ,
    NETDATA_OPT_SWAP,
    NETDATA_OPT_VFS,
    NETDATA_OPT_NFS,
    NETDATA_OPT_XFS,
    NETDATA_OPT_ZFS,

    NETDATA_OPT_HELP,
    NETDATA_OPT_ALL,
    NETDATA_OPT_COMMON,
    NETDATA_OPT_LOAD_BINARY,
    NETDATA_OPT_NETDATA_PATH,
    NETDATA_OPT_LOG_PATH,
    NETDATA_OPT_CONTENT,
    NETDATA_OPT_ITERATION,
    NETDATA_OPT_PID
};

typedef struct ebpf_specify_name {
    char *program_name;
    char *function_to_attach;
    char *optional;
    bool retprobe;
} ebpf_specify_name_t;

typedef struct ebpf_module {
    uint32_t kernels;
    uint64_t flags;
    char *name;
    ebpf_specify_name_t *update_names;
    char *ctrl_table;
} ebpf_module_t ;

typedef struct ebpf_attach {
    struct bpf_link **links;
    size_t success;
    size_t fail;
} ebpf_attach_t;

typedef struct ebpf_table_data {
    void *key;
    void *next_key;
    void *value;
    void *def_value;

    long key_length;
    long value_length;

    size_t filled;
    size_t zero;
} ebpf_table_data_t;

#endif  /* NETDATA_LEGACY_TESTER */

