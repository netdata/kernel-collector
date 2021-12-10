#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "netdata_core.h"
#include "netdata_disk.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

//Hardware
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, block_key_t);
    __type(value, __u64);
    __uint(max_entries, NETDATA_DISK_HISTOGRAM_LENGTH);
} tbl_disk_iocall SEC(".maps");

// Temporary use only
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, netdata_disk_key_t);
    __type(value, __u64);
    __uint(max_entries, 8192);
} tmp_disk_tp_stat SEC(".maps");


/************************************************************************************
 *     
 *                                 DISK SECTION
 *     
 ***********************************************************************************/

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

    // calculate and convert to microsecond
    u64 curr = bpf_ktime_get_ns();
    __u64 data, *update;
    curr -= *fill;
    curr /= 1000;

    blk.bin = libnetdata_select_idx(curr, NETDATA_FS_MAX_BINS_POS);
    blk.dev = netdata_new_encode_dev(ptr->dev);

    // Update IOPS
    update = bpf_map_lookup_elem(&tbl_disk_iocall ,&blk);
    if (update) {
        libnetdata_update_u64(update, 1);
    } else {
        data = 1;
        bpf_map_update_elem(&tbl_disk_iocall, &blk, &data, BPF_ANY);
    }

    bpf_map_delete_elem(&tmp_disk_tp_stat, &key);

    return 0;
}

char _license[] SEC("license") = "GPL";

