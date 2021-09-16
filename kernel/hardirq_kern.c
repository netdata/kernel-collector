#define KBUILD_MODNAME "hardirq_netdata"
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/genhd.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,4,14))
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#else
#include "netdata_bpf_helpers.h"
#endif
#include "netdata_ebpf.h"


/************************************************************************************
 *                                 MAPS
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,4,14))
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, hardirq_key_t);
    __type(value, hardirq_val_t);
    __uint(max_entries, NETDATA_HARDIRQ_MAX_IRQS);
} tbl_hardirq SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, hardirq_static_val_t);
    __uint(max_entries, NETDATA_HARDIRQ_STATIC_END);
} tbl_hardirq_static SEC(".maps");

#else
struct bpf_map_def SEC("maps") tbl_hardirq = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(hardirq_key_t),
    .value_size = sizeof(hardirq_val_t),
    .max_entries = NETDATA_HARDIRQ_MAX_IRQS
};

// maps from enum index to latency.
struct bpf_map_def SEC("maps") tbl_hardirq_static = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(hardirq_static_val_t),
    .max_entries = NETDATA_HARDIRQ_STATIC_END
};
#endif

/************************************************************************************
 *                                HARDIRQ SECTION
 ***********************************************************************************/

SEC("tracepoint/irq/irq_handler_entry")
int netdata_irq_handler_entry(struct netdata_irq_handler_entry *ptr)
{
    hardirq_key_t key = {};
    hardirq_val_t *valp, val = {};

    key.irq = ptr->irq;
    valp = bpf_map_lookup_elem(&tbl_hardirq, &key);
    if (valp) {
        valp->ts = bpf_ktime_get_ns();
    } else {
        val.latency = 0;
        val.ts = bpf_ktime_get_ns();
        TP_DATA_LOC_READ_CONST(val.name, ptr, ptr->data_loc_name, NETDATA_HARDIRQ_NAME_LEN);
        bpf_map_update_elem(&tbl_hardirq, &key, &val, BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/irq/irq_handler_exit")
int netdata_irq_handler_exit(struct netdata_irq_handler_exit *ptr)
{
    hardirq_key_t key = {};
    hardirq_val_t *valp;

    key.irq = ptr->irq;
    valp = bpf_map_lookup_elem(&tbl_hardirq, &key);
    if (!valp) {
        return 0;
    }

    // get time diff and convert to microseconds.
    u64 latency = (bpf_ktime_get_ns() - valp->ts) / 1000;
    libnetdata_update_u64(&valp->latency, latency);

    return 0;
}

/************************************************************************************
 *                                HARDIRQ STATIC
 ***********************************************************************************/

#define HARDIRQ_STATIC_GEN_ENTRY(__type, __enum_idx)                          \
int netdata_irq_ ##__type(struct netdata_irq_vectors_entry *ptr)              \
{                                                                             \
    u32 idx;                                                                  \
    hardirq_static_val_t *valp, val = {};                                     \
                                                                              \
    idx = __enum_idx;                                                         \
    valp = bpf_map_lookup_elem(&tbl_hardirq_static, &idx);                    \
    if (valp) {                                                               \
        valp->ts = bpf_ktime_get_ns();                                        \
    } else {                                                                  \
        val.latency = 0;                                                      \
        val.ts = bpf_ktime_get_ns();                                          \
        bpf_map_update_elem(&tbl_hardirq_static, &idx, &val, BPF_ANY);        \
    }                                                                         \
                                                                              \
    return 0;                                                                 \
}

#define HARDIRQ_STATIC_GEN_EXIT(__type, __enum_idx)                           \
int netdata_irq_ ##__type(struct netdata_irq_vectors_exit *ptr)               \
{                                                                             \
    u32 idx;                                                                  \
    hardirq_static_val_t *valp;                                               \
                                                                              \
    idx = __enum_idx;                                                         \
    valp = bpf_map_lookup_elem(&tbl_hardirq_static, &idx);                    \
    if (!valp) {                                                              \
        return 0;                                                             \
    }                                                                         \
                                                                              \
    /* get time diff and convert to microseconds. */                          \
    u64 latency = (bpf_ktime_get_ns() - valp->ts) / 1000;                     \
    libnetdata_update_u64(&valp->latency, latency);                           \
                                                                              \
    return 0;                                                                 \
}

SEC("tracepoint/irq_vectors/thermal_apic_entry")
HARDIRQ_STATIC_GEN_ENTRY(
    thermal_apic_entry,
    NETDATA_HARDIRQ_STATIC_APIC_THERMAL
)
SEC("tracepoint/irq_vectors/thermal_apic_exit")
HARDIRQ_STATIC_GEN_EXIT(
    thermal_apic_exit,
    NETDATA_HARDIRQ_STATIC_APIC_THERMAL
)

SEC("tracepoint/irq_vectors/threshold_apic_entry")
HARDIRQ_STATIC_GEN_ENTRY(
    threshold_apic_entry,
    NETDATA_HARDIRQ_STATIC_APIC_THRESHOLD
)
SEC("tracepoint/irq_vectors/threshold_apic_exit")
HARDIRQ_STATIC_GEN_EXIT(
    threshold_apic_exit,
    NETDATA_HARDIRQ_STATIC_APIC_THRESHOLD
)

SEC("tracepoint/irq_vectors/error_apic_entry")
HARDIRQ_STATIC_GEN_ENTRY(
    error_apic_entry,
    NETDATA_HARDIRQ_STATIC_APIC_ERROR
)
SEC("tracepoint/irq_vectors/error_apic_exit")
HARDIRQ_STATIC_GEN_EXIT(
    error_apic_exit,
    NETDATA_HARDIRQ_STATIC_APIC_ERROR
)

SEC("tracepoint/irq_vectors/deferred_error_apic_entry")
HARDIRQ_STATIC_GEN_ENTRY(
    deferred_error_apic_entry,
    NETDATA_HARDIRQ_STATIC_APIC_DEFERRED_ERROR
)
SEC("tracepoint/irq_vectors/deferred_error_apic_exit")
HARDIRQ_STATIC_GEN_EXIT(
    deferred_error_apic_exit,
    NETDATA_HARDIRQ_STATIC_APIC_DEFERRED_ERROR
)

SEC("tracepoint/irq_vectors/spurious_apic_entry")
HARDIRQ_STATIC_GEN_ENTRY(
    spurious_apic_entry,
    NETDATA_HARDIRQ_STATIC_APIC_SPURIOUS
)
SEC("tracepoint/irq_vectors/spurious_apic_exit")
HARDIRQ_STATIC_GEN_EXIT(
    spurious_apic_exit,
    NETDATA_HARDIRQ_STATIC_APIC_SPURIOUS
)

SEC("tracepoint/irq_vectors/call_function_entry")
HARDIRQ_STATIC_GEN_ENTRY(
    call_function_entry,
    NETDATA_HARDIRQ_STATIC_FUNC_CALL
)
SEC("tracepoint/irq_vectors/call_function_exit")
HARDIRQ_STATIC_GEN_EXIT(
    call_function_exit,
    NETDATA_HARDIRQ_STATIC_FUNC_CALL
)

SEC("tracepoint/irq_vectors/call_function_single_entry")
HARDIRQ_STATIC_GEN_ENTRY(
    call_function_single_entry,
    NETDATA_HARDIRQ_STATIC_FUNC_CALL_SINGLE
)
SEC("tracepoint/irq_vectors/call_function_single_exit")
HARDIRQ_STATIC_GEN_EXIT(
    call_function_single_exit,
    NETDATA_HARDIRQ_STATIC_FUNC_CALL_SINGLE
)

SEC("tracepoint/irq_vectors/reschedule_entry")
HARDIRQ_STATIC_GEN_ENTRY(
    reschedule_entry,
    NETDATA_HARDIRQ_STATIC_RESCHEDULE
)
SEC("tracepoint/irq_vectors/reschedule_exit")
HARDIRQ_STATIC_GEN_EXIT(
    reschedule_exit,
    NETDATA_HARDIRQ_STATIC_RESCHEDULE
)

SEC("tracepoint/irq_vectors/local_timer_entry")
HARDIRQ_STATIC_GEN_ENTRY(
    local_timer_entry,
    NETDATA_HARDIRQ_STATIC_LOCAL_TIMER
)
SEC("tracepoint/irq_vectors/local_timer_exit")
HARDIRQ_STATIC_GEN_EXIT(
    local_timer_exit,
    NETDATA_HARDIRQ_STATIC_LOCAL_TIMER
)

SEC("tracepoint/irq_vectors/irq_work_entry")
HARDIRQ_STATIC_GEN_ENTRY(
    irq_work_entry,
    NETDATA_HARDIRQ_STATIC_IRQ_WORK
)
SEC("tracepoint/irq_vectors/irq_work_exit")
HARDIRQ_STATIC_GEN_EXIT(
    irq_work_exit,
    NETDATA_HARDIRQ_STATIC_IRQ_WORK
)

SEC("tracepoint/irq_vectors/x86_platform_ipi_entry")
HARDIRQ_STATIC_GEN_ENTRY(
    x86_platform_ipi_entry,
    NETDATA_HARDIRQ_STATIC_X86_PLATFORM_IPI
)
SEC("tracepoint/irq_vectors/x86_platform_ipi_exit")
HARDIRQ_STATIC_GEN_EXIT(
    x86_platform_ipi_exit,
    NETDATA_HARDIRQ_STATIC_X86_PLATFORM_IPI
)

char _license[] SEC("license") = "GPL";

