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

NETDATA_BPF_PERCPU_HASH_DEF(tbl_disk_iocall, block_key_t, __u64, NETDATA_DISK_HISTOGRAM_LENGTH);
NETDATA_BPF_HASH_DEF(tmp_disk_tp_stat, netdata_disk_key_t, __u64, 8192);
NETDATA_BPF_ARRAY_DEF(disk_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

SEC("tracepoint/block/block_rq_issue")
int netdata_block_rq_issue(struct netdata_block_rq_issue *ptr)
{
    if (!ptr->dev)
        return 0;

    netdata_disk_key_t key = {
        .dev = ptr->dev,
        .sector = (ptr->sector < 0) ? 0 : ptr->sector
    };

    __u64 value = bpf_ktime_get_ns();
    bpf_map_update_elem(&tmp_disk_tp_stat, &key, &value, BPF_ANY);

    libnetdata_update_global(&disk_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);

    return 0;
}

SEC("tracepoint/block/block_rq_complete")
int netdata_block_rq_complete(struct netdata_block_rq_complete *ptr)
{
    netdata_disk_key_t key = {
        .dev = ptr->dev,
        .sector = (ptr->sector < 0) ? 0 : ptr->sector
    };

    __u64 *fill = bpf_map_lookup_elem(&tmp_disk_tp_stat, &key);
    if (!fill)
        return 0;

    u64 curr = bpf_ktime_get_ns();
    curr -= *fill;
    curr /= 1000;

    block_key_t blk = {
        .bin = libnetdata_select_idx(curr, NETDATA_FS_MAX_BINS_POS),
        .dev = netdata_new_encode_dev(ptr->dev)
    };

    __u64 data = 1;
    __u64 *update = bpf_map_lookup_elem(&tbl_disk_iocall, &blk);
    if (update) {
        libnetdata_update_u64(update, 1);
    } else {
        bpf_map_update_elem(&tbl_disk_iocall, &blk, &data, BPF_ANY);
    }

    bpf_map_delete_elem(&tmp_disk_tp_stat, &key);

    libnetdata_update_global(&disk_ctrl, NETDATA_CONTROLLER_PID_TABLE_DEL, 1);

    return 0;
}

char _license[] SEC("license") = "GPL";

