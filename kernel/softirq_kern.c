#define KBUILD_MODNAME "softirq_netdata"
#include <linux/ptrace.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "netdata_ebpf.h"

/************************************************************************************
 *                                 MAPS
 ***********************************************************************************/

NETDATA_BPF_PERCPU_ARRAY_DEF(tbl_softirq, __u32, softirq_val_t, NETDATA_SOFTIRQ_MAX_IRQS);

/************************************************************************************
 *                                SOFTIRQ SECTION
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
