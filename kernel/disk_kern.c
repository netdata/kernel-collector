#define KBUILD_MODNAME "disk_netdata"
#include <linux/version.h>
#include <linux/blk-mq.h>
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
NETDATA_BPF_HASH_DEF(tmp_disk_tp_stat, __u64, netdata_disk_inflight_t, 8192);
NETDATA_BPF_ARRAY_DEF(disk_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

/************************************************************************************
 *
 *                                 Helper Functions
 *
 ***********************************************************************************/

static __always_inline netdata_disk_key_t netdata_disk_key(void *ptr)
{
    struct netdata_block_rq_issue *issue = ptr;
    netdata_disk_key_t key = {
        .dev = issue->dev,
        .pad = 0,
        .sector = (issue->sector < 0) ? 0 : issue->sector
    };
    return key;
}

static __always_inline int netdata_disk_request_key(struct request *rq, netdata_disk_key_t *key)
{
    struct request_queue *queue = NULL;
    struct gendisk *disk = NULL;
    struct block_device *part = NULL;

    if (!rq)
        return 0;

    bpf_probe_read(&queue, sizeof(queue), &rq->q);
    if (!queue)
        return 0;
    bpf_probe_read(&disk, sizeof(disk), &queue->disk);
    if (!disk)
        return 0;
    bpf_probe_read(&part, sizeof(part), &disk->part0);
    if (!part)
        return 0;

    key->dev = 0;
    key->pad = 0;
    key->sector = 0;
    bpf_probe_read(&key->dev, sizeof(key->dev), &part->bd_dev);
    bpf_probe_read(&key->sector, sizeof(key->sector), &rq->__sector);
    if (!key->dev)
        return 0;
    if ((s64)key->sector < 0)
        key->sector = 0;
    return 1;
}

/************************************************************************************
 *
 *                             Request Probes
 *
 ***********************************************************************************/

SEC("kprobe/blk_mq_start_request")
int netdata_block_rq_issue(struct pt_regs *ctx)
{
    struct request *rq = (struct request *)PT_REGS_PARM1(ctx);
    netdata_disk_key_t disk_key = { };
    if (!netdata_disk_request_key(rq, &disk_key))
        return 0;

    __u64 request_key = (__u64)rq;
    netdata_disk_inflight_t value = {
        .timestamp = bpf_ktime_get_ns(),
        .key = disk_key,
    };
    if (bpf_map_update_elem(&tmp_disk_tp_stat, &request_key, &value, BPF_ANY))
        return 0;

    libnetdata_update_global(&disk_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);

    return 0;
}

SEC("kprobe/blk_mq_end_request")
int netdata_block_rq_complete(struct pt_regs *ctx)
{
    struct request *rq = (struct request *)PT_REGS_PARM1(ctx);
    __u64 request_key = (__u64)rq;

    netdata_disk_inflight_t *fill = bpf_map_lookup_elem(&tmp_disk_tp_stat, &request_key);
    if (!fill)
        return 0;

    __u64 curr = bpf_ktime_get_ns() - fill->timestamp;
    curr /= 1000;

    block_key_t blk = {
        .bin = libnetdata_select_idx(curr, NETDATA_FS_MAX_BINS_POS),
        .dev = netdata_new_encode_dev(fill->key.dev)
    };

    __u64 *update = bpf_map_lookup_elem(&tbl_disk_iocall, &blk);
    if (update) {
        libnetdata_update_u64(update, 1);
    } else {
        bpf_map_update_elem(&tbl_disk_iocall, &blk, &(__u64){1}, BPF_ANY);
    }

    bpf_map_delete_elem(&tmp_disk_tp_stat, &request_key);

    libnetdata_update_global(&disk_ctrl, NETDATA_CONTROLLER_PID_TABLE_DEL, 1);

    return 0;
}

/* Legacy request queues complete through this non-exported block-layer path. */
SEC("kprobe/blk_complete_request")
int netdata_blk_complete_request(struct pt_regs *ctx)
{
    return netdata_block_rq_complete(ctx);
}

char _license[] SEC("license") = "GPL";
