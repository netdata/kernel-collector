#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "netdata_core.h"
#include "netdata_mdflush.h"

// Copied from https://elixir.bootlin.com/linux/v5.16-rc2/source/include/uapi/linux/major.h
// that has the same value of https://elixir.bootlin.com/linux/v4.14/source/include/uapi/linux/major.h#L25
#define NETDATA_MD_MAJOR 9


// Preprocessors copied from https://elixir.bootlin.com/linux/v4.14/source/include/linux/kdev_t.h#L10
// they are the same in https://elixir.bootlin.com/linux/v5.16-rc2/source/include/linux/kdev_t.h
#define NETDATA_MINORBITS	20
#define NETDATA_MINORMASK	((1U << NETDATA_MINORBITS) - 1)

#define NETDATA_MAJOR(dev)	((unsigned int) ((dev) >> NETDATA_MINORBITS))
#define NETDATA_MINOR(dev)	((unsigned int) ((dev) & NETDATA_MINORMASK))

// Preprocessor copied from https://elixir.bootlin.com/linux/v5.16-rc2/source/include/uapi/linux/raid/md_u.h#L69
// Like the previous value is not changing between versions
/* 63 partitions with the alternate major number (mdp) */
#define Netdata_MdpMinorShift 6

/************************************************************************************
 *
 *                                 MAPS
 *
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, mdflush_key_t);
    __type(value, mdflush_val_t);
    __uint(max_entries, 1024);
} tbl_mdflush SEC(".maps");

/************************************************************************************
 *
 *                              COMMON SECTION
 *
 ***********************************************************************************/

static int netdata_md_common(struct mddev *mddev)
{
    mdflush_key_t key = 0;
    mdflush_val_t *valp, val;

    // get correct key.
    // this essentially does the logic here:
    // https://elixir.bootlin.com/linux/v4.14/source/drivers/md/md.c#L5256
    bpf_probe_read(&key, sizeof(key), &mddev->unit);
    int partitioned = (NETDATA_MAJOR(key) != NETDATA_MD_MAJOR);
    int shift = partitioned ? Netdata_MdpMinorShift : 0;
    key = NETDATA_MINOR(key) >> shift;

    valp = bpf_map_lookup_elem(&tbl_mdflush, &key);
    if (valp) {
        *valp += 1;
    } else {
        val = 1;
        bpf_map_update_elem(&tbl_mdflush, &key, &val, BPF_ANY);
    }

    return 0;
}

/************************************************************************************
 *
 *                           MDFLUSH SECTION(kprobe)
 *
 ***********************************************************************************/

SEC("kprobe/md_flush_request")
int BPF_KPROBE(netdata_md_flush_request_kprobe)
{
    struct mddev *mddev = (struct mddev *)PT_REGS_PARM1(ctx);

    return netdata_md_common(mddev);
}

/************************************************************************************
 *
 *                           MDFLUSH SECTION(trampoline)
 *
 ***********************************************************************************/

SEC("fentry/md_flush_request")
int BPF_PROG(netdata_md_flush_request_fentry, struct mddev *mddev)
{
    return netdata_md_common(mddev);
}

char _license[] SEC("license") = "GPL";

