// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_HARDIRQ_H_
#define _NETDATA_HARDIRQ_H_ 1

#define NETDATA_HARDIRQ_MAX_IRQS 1024L
#define NETDATA_HARDIRQ_NAME_LEN 32

// /sys/kernel/debug/tracing/events/irq/irq_handler_entry/
struct netdata_irq_handler_entry {
    u64 pad;                    // This is not used with eBPF
    int irq;                    // offset:8;       size:4; signed:1;
    int data_loc_name;          // offset:12;      size:4; signed:1; (https://github.com/iovisor/bpftrace/issues/385)
                                // (https://lists.linuxfoundation.org/pipermail/iovisor-dev/2017-February/000627.html)
};

// /sys/kernel/debug/tracing/events/irq/irq_handler_exit/
// https://elixir.bootlin.com/linux/latest/source/include/trace/events/block.h
struct netdata_irq_handler_exit {
    u64 pad;                    // This is not used with eBPF
    int irq;                    // offset:8;       size:4; signed:1;
    int ret;                    // offset:12;      size:4; signed:1;
};

typedef struct hardirq_key {
    int irq;
} hardirq_key_t;

typedef struct hardirq_val {
    // incremental counter storing the total latency so far.
    u64 latency;

    // temporary timestamp stored at the IRQ entry handler, to be diff'd with a
    // timestamp at the IRQ exit handler, to get the latency to add to the
    // `latency` field.
    u64 ts;

    // identifies the IRQ with a human-readable string.
    char name[NETDATA_HARDIRQ_NAME_LEN];
} hardirq_val_t;

#endif /* _NETDATA_HARDIRQ_H_ */
