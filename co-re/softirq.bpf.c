#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "netdata_core.h"
#include "netdata_softirq.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, __u32);
        __type(value, softirq_val_t);
        __uint(max_entries, NETDATA_SOFTIRQ_MAX_IRQS);
} tbl_softirq SEC(".maps");

/***********************************************************************************
 *
 *                           SOFTIRQ SECTION(tracepoint)
 *
 ***********************************************************************************/

SEC("tracepoint/irq/softirq_entry")
int netdata_softirq_entry(struct netdata_softirq_entry *ptr)
{
    softirq_val_t *valp, val = {};
    u32 vec = ptr->vec;

    // out-of-range index.
    if (vec > NETDATA_SOFTIRQ_MAX_IRQS-1) {
        return 0;
    }

    valp = bpf_map_lookup_elem(&tbl_softirq, &vec);
    if (valp) {
        valp->ts = bpf_ktime_get_ns();
    } else {
        val.latency = 0;
        val.ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&tbl_softirq, &vec, &val, BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/irq/softirq_exit")
int netdata_softirq_exit(struct netdata_softirq_exit *ptr)
{
    softirq_val_t *valp;
    u32 vec = ptr->vec;

    // out-of-range index.
    if (vec > NETDATA_SOFTIRQ_MAX_IRQS-1) {
        return 0;
    }

    valp = bpf_map_lookup_elem(&tbl_softirq, &vec);
    if (!valp) {
        return 0;
    }

    // get time diff and convert to microseconds.
    u64 latency = (bpf_ktime_get_ns() - valp->ts) / 1000;
    libnetdata_update_u64(&valp->latency, latency);

    return 0;
}

char _license[] SEC("license") = "GPL";

