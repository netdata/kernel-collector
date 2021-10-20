#define KBUILD_MODNAME "mdflush_netdata"
#include <linux/bpf.h>
#include <drivers/md/md.h>
#include <linux/raid/md_u.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,4,14))
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#else
#include "netdata_bpf_helpers.h"
#endif
#include "netdata_ebpf.h"

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5,4,14))
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, mdflush_key_t);
    __type(value, mdflush_val_t);
    __uint(max_entries, 1024);
} tbl_mdflush SEC(".maps");

#else

struct bpf_map_def SEC("maps") tbl_mdflush = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(mdflush_key_t),
    .value_size = sizeof(mdflush_val_t),
    .max_entries = 1024
};
#endif

SEC("kprobe/md_flush_request")
int netdata_md_flush_request(struct pt_regs *ctx)
{
    mdflush_key_t key = 0;
    mdflush_val_t *valp, val;
    struct mddev *mddev = (struct mddev *)PT_REGS_PARM1(ctx);

    // get correct key.
    // this essentially does the logic here:
    // https://elixir.bootlin.com/linux/v4.14/source/drivers/md/md.c#L5256
    bpf_probe_read(&key, sizeof(key), &mddev->unit);
    int partitioned = (MAJOR(key) != MD_MAJOR);
    int shift = partitioned ? MdpMinorShift : 0;
    key = MINOR(key) >> shift;

    valp = bpf_map_lookup_elem(&tbl_mdflush, &key);
    if (valp) {
        *valp += 1;
    } else {
        val = 1;
        bpf_map_update_elem(&tbl_mdflush, &key, &val, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
