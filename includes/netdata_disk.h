// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_DISK_H_
#define _NETDATA_DISK_H_ 1

#include "netdata_fs.h"

#define NETDATA_DISK_MAX_HD 256L
#define NETDATA_DISK_HISTOGRAM_LENGTH  (NETDATA_FS_MAX_BINS * NETDATA_DISK_MAX_HD)

// Decode function extracted from: https://elixir.bootlin.com/linux/v5.10.8/source/include/linux/kdev_t.h#L7
#define NETDATA_MINORBITS       20
#define NETDATA_MINORMASK	((1U << NETDATA_MINORBITS) - 1)

#define NETDATA_MAJOR(dev)	((unsigned int) ((dev) >> NETDATA_MINORBITS))
#define NETDATA_MINOR(dev)	((unsigned int) ((dev) & NETDATA_MINORMASK))
#define NETDATA_MKDEV(ma,mi)    (((ma) << MINORBITS) | (mi))

static __always_inline u32 netdata_new_encode_dev(dev_t dev)
{
    unsigned major = NETDATA_MAJOR(dev);
    unsigned minor = NETDATA_MINOR(dev);
    return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

// /sys/kernel/debug/tracing/events/block/block_rq_issue/
struct netdata_block_rq_issue {
    u64 pad;                    // This is not used with eBPF
    dev_t dev;                  // offset:8;       size:4; signed:0;
    sector_t sector;            // offset:16;      size:8; signed:0;
    unsigned int nr_sector;     // offset:24;      size:4; signed:0;
    unsigned int bytes;         // offset:28;      size:4; signed:0;
    char rwbs[8];               // offset:32;      size:8; signed:1;
    char comm[16];              // offset:40;      size:16;        signed:1;
    int data_loc_name;          // offset:56;      size:4; signed:1; (https://github.com/iovisor/bpftrace/issues/385)
};

// /sys/kernel/debug/tracing/events/block/block_rq_complete
// https://elixir.bootlin.com/linux/latest/source/include/trace/events/block.h
struct netdata_block_rq_complete {
    u64 pad;                    // This is not used with eBPF
    dev_t dev;                  // offset:8;       size:4; signed:0;
    sector_t sector;            // offset:16;      size:8; signed:0;
    unsigned int nr_sector;     // offset:24;      size:4; signed:0;
    int error;                  // offset:28;      size:4; signed:1;
    char rwbs[8];               // offset:32;      size:8; signed:1;
    int data_loc_name;          // offset:40;      size:4; signed:1; 
                                //(https://lists.linuxfoundation.org/pipermail/iovisor-dev/2017-February/000627.html)
};

typedef struct netdata_disk_key {
    dev_t dev;
    sector_t sector;
} netdata_disk_key_t;

typedef struct block_key {
    __u32 bin;
    u32 dev;
} block_key_t;

#endif /* _NETDATA_DISK_H_ */

