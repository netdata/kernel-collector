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

/************************************************************************************
 *                                HARDIRQ STATIC
 ***********************************************************************************/

// all of the `irq_vectors` events, except `vector_*`, have the same format.
// cat /sys/kernel/debug/tracing/available_events | grep 'irq_vectors' | grep -v ':vector_'
struct netdata_irq_vectors_entry {
    u64 pad;                    // This is not used with eBPF
    int vector;                 // offset:8;       size:4; signed:1;
};
struct netdata_irq_vectors_exit {
    u64 pad;                    // This is not used with eBPF
    int vector;                 // offset:8;       size:4; signed:1;
};

// these represent static IRQs that aren't given an IRQ ID like the ones above.
// they each require separate entry/exit tracepoints to track.
enum netdata_hardirq_static {
    NETDATA_HARDIRQ_STATIC_APIC_THERMAL,
    NETDATA_HARDIRQ_STATIC_APIC_THRESHOLD,
    NETDATA_HARDIRQ_STATIC_APIC_ERROR,
    NETDATA_HARDIRQ_STATIC_APIC_DEFERRED_ERROR,
    NETDATA_HARDIRQ_STATIC_APIC_SPURIOUS,
    NETDATA_HARDIRQ_STATIC_FUNC_CALL,
    NETDATA_HARDIRQ_STATIC_FUNC_CALL_SINGLE,
    NETDATA_HARDIRQ_STATIC_RESCHEDULE,
    NETDATA_HARDIRQ_STATIC_LOCAL_TIMER,
    NETDATA_HARDIRQ_STATIC_IRQ_WORK,
    NETDATA_HARDIRQ_STATIC_X86_PLATFORM_IPI,

    // must be last; used as counter.
    NETDATA_HARDIRQ_STATIC_END
};

typedef struct hardirq_static_val {
    // incremental counter storing the total latency so far.
    u64 latency;

    // temporary timestamp stored at the IRQ entry handler, to be diff'd with a
    // timestamp at the IRQ exit handler, to get the latency to add to the
    // `latency` field.
    u64 ts;
} hardirq_static_val_t;

#endif /* _NETDATA_HARDIRQ_H_ */
