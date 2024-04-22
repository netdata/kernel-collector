#define KBUILD_MODNAME "mdflush_netdata"
#include <drivers/md/md.h>
#include <linux/raid/md_u.h>
#include <uapi/linux/major.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "netdata_ebpf.h"

struct {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    __uint(type, BPF_MAP_TYPE_HASH);
#else
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#endif
    __type(key, mdflush_key_t);
    __type(value, mdflush_val_t);
    __uint(max_entries, 1024);
} tbl_mdflush SEC(".maps");

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
