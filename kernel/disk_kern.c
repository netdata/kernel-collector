#define KBUILD_MODNAME "disk_netdata"
#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0))
#include <linux/genhd.h>
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(6,0,0))
#include <linux/kdev_t.h>
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "netdata_ebpf.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
//Hardware
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, block_key_t);
    __type(value, __u64);
    __uint(max_entries, NETDATA_DISK_HISTOGRAM_LENGTH);
} tbl_disk_iocall SEC(".maps");

// Temporary use only
struct {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    __uint(type, BPF_MAP_TYPE_HASH);
#else
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#endif
    __type(key, netdata_disk_key_t);
    __type(value, __u64);
    __uint(max_entries, 8192);
} tmp_disk_tp_stat SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} disk_ctrl SEC(".maps");

#else

//Hardware
struct bpf_map_def SEC("maps") tbl_disk_iocall = {
    .type = BPF_MAP_TYPE_HASH,
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

struct bpf_map_def SEC("maps") disk_ctrl = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_CONTROLLER_END
};

#endif

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

    libnetdata_update_global(&disk_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);

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
    blk.dev = new_encode_dev(ptr->dev);

    // Update IOPS
    update = bpf_map_lookup_elem(&tbl_disk_iocall ,&blk);
    if (update) {
        libnetdata_update_u64(update, 1);
    } else {
        data = 1;
        bpf_map_update_elem(&tbl_disk_iocall, &blk, &data, BPF_ANY);
    }

    bpf_map_delete_elem(&tmp_disk_tp_stat, &key);

    libnetdata_update_global(&disk_ctrl, NETDATA_CONTROLLER_PID_TABLE_DEL, 1);

    return 0;
}

char _license[] SEC("license") = "GPL";

