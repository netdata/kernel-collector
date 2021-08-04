#define KBUILD_MODNAME "hardirq_netdata"
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/genhd.h>

#include "bpf_helpers.h"
#include "netdata_ebpf.h"

/************************************************************************************
 *
 *                                 MAPS
 *
 ***********************************************************************************/

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

/************************************************************************************
 *
 *                                HARDIRQ SECTION
 *
 ***********************************************************************************/

SEC("tracepoint/irq/irq_handler_entry")
int netdata_irq_handler_entry(struct netdata_irq_handler_entry *ptr)
{
    hardirq_key_t key = {};
    hardirq_val_t *valp, val = {};

    key.irq = ptr->irq;
    valp = bpf_map_lookup_elem(&tbl_hardirq, &key);
    if (!valp) {
        valp = &val;
        val.latency = 0;
        TP_DATA_LOC_READ_CONST(val.name, ptr, ptr->data_loc_name, NETDATA_HARDIRQ_NAME_LEN);
    }

    valp->ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&tbl_hardirq, &key, valp, BPF_ANY);

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

char _license[] SEC("license") = "GPL";
