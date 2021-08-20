#define KBUILD_MODNAME "softirq_netdata"
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/genhd.h>

#include "bpf_helpers.h"
#include "netdata_ebpf.h"

/************************************************************************************
 *                                 MAPS
 ***********************************************************************************/

// maps from irq index to latency.
// there are only 10 software IRQs, all statically defined in the kernel.
struct bpf_map_def SEC("maps") tbl_softirq = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(softirq_val_t),
    .max_entries = 10
};

/************************************************************************************
 *                                SOFTIRQ SECTION
 ***********************************************************************************/

SEC("tracepoint/irq/softirq_entry")
int netdata_softirq_entry(struct netdata_softirq_entry *ptr)
{
    softirq_val_t *valp, val = {};

    valp = bpf_map_lookup_elem(&tbl_softirq, &ptr->vec);
    if (!valp) {
        valp = &val;
        val.latency = 0;
    }

    valp->ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&tbl_softirq, &ptr->vec, valp, BPF_ANY);

    return 0;
}

SEC("tracepoint/irq/softirq_exit")
int netdata_softirq_exit(struct netdata_softirq_exit *ptr)
{
    softirq_val_t *valp;

    valp = bpf_map_lookup_elem(&tbl_softirq, &ptr->vec);
    if (!valp) {
        return 0;
    }

    // get time diff and convert to microseconds.
    u64 latency = (bpf_ktime_get_ns() - valp->ts) / 1000;
    libnetdata_update_u64(&valp->latency, latency);

    return 0;
}
