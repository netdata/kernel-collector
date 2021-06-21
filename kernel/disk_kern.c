#define KBUILD_MODNAME "disk_netdata"
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

//Hardware
struct bpf_map_def SEC("maps") tbl_disk_rcall = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(block_key_t),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_DISK_HISTOGRAM_LENGTH
};

struct bpf_map_def SEC("maps") tbl_disk_wcall = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(block_key_t),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_DISK_HISTOGRAM_LENGTH
};

// Temporary use only
struct bpf_map_def SEC("maps") tmp_disk_tp_stat = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(netdata_disk_key_t),
    .value_size = sizeof(__u64),
    .max_entries = 8192
};

/************************************************************************************
 *     
 *                                 DISK SECTION
 *     
 ***********************************************************************************/

// Probably it is available after 4.13 only

SEC("tracepoint/block/block_rq_issue")
int netdata_block_rq_issue(struct netdata_block_rq_issue *ptr)
{
    // blkid generates these and we're not interested in them
    if (!ptr->dev)
        return 0;

    netdata_disk_key_t key = {};
    key.dev = ptr->dev;
    key.sector = ptr->sector;

    if (key.sector < 0)
        key.sector = 0;

    __u64 value = bpf_ktime_get_ns();

    bpf_map_update_elem(&tmp_disk_tp_stat, &key, &value, BPF_ANY);

    return 0;
}

SEC("tracepoint/block/block_rq_complete")
int netdata_block_rq_complete(struct netdata_block_rq_complete *ptr)
{
    __u64 *fill;
    netdata_disk_key_t key = {};
    block_key_t blk = {};
    key.dev = ptr->dev;
    key.sector = ptr->sector;

    if (key.sector < 0)
        key.sector = 0;

    fill = bpf_map_lookup_elem(&tmp_disk_tp_stat ,&key);
    if (!fill)
        return 0;

    // W - write
    // S - Sync
    int selector = ((ptr->rwbs[0] == 'F') || (ptr->rwbs[0] == 'S') || (ptr->rwbs[0] == 'W') ||
                    (ptr->rwbs[1] == 'F') || (ptr->rwbs[1] == 'S') || (ptr->rwbs[0] == 'W'));

    // calculate and convert to microsecond
    u64 curr = bpf_ktime_get_ns();
    __u64 data, *update;
    curr -= *fill;
    curr /= 1000;

    blk.bin = libnetdata_select_idx(curr, NETDATA_FS_MAX_BINS_POS);
    blk.dev = new_encode_dev(ptr->dev);

    // Update IOPS
    struct bpf_map_def *tbl = (!selector)?&tbl_disk_rcall:&tbl_disk_wcall;
    update = bpf_map_lookup_elem(tbl ,&blk);
    if (update) {
        libnetdata_update_u64(update, 1);
    } else {
        data = 1;
        bpf_map_update_elem(tbl, &blk, &data, BPF_ANY);
    }

    bpf_map_delete_elem(&tmp_disk_tp_stat, &key);

    return 0;
}

char _license[] SEC("license") = "GPL";

