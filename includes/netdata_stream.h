// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_STREAM_H_
#define _NETDATA_STREAM_H_ 1

#include "netdata_arena_common.h"

#define NETDATA_STREAM_RINGBUF_SIZE (1 << 20)

enum netdata_stream_action {
    NETDATA_STREAM_CALL = 1,
    NETDATA_STREAM_MOUNT = 2,
    NETDATA_STREAM_UMOUNT = 3,
    NETDATA_STREAM_MD_FLUSH = 4,
    NETDATA_STREAM_DISK_COMPLETE = 5,
    NETDATA_STREAM_NV_ACCEPT = 16,
    NETDATA_STREAM_NV_TCP_SEND = 17,
    NETDATA_STREAM_NV_TCP_RETRANSMIT = 18,
    NETDATA_STREAM_NV_TCP_STATE = 19,
    NETDATA_STREAM_NV_TCP_RECEIVE = 20,
    NETDATA_STREAM_NV_TCP_V4_CONNECT = 21,
    NETDATA_STREAM_NV_TCP_V6_CONNECT = 22,
    NETDATA_STREAM_NV_TCP_CLOSE = 23,
    NETDATA_STREAM_NV_UDP_RECEIVE = 24,
    NETDATA_STREAM_NV_UDP_SEND = 25,
};

struct netdata_stream_event_t {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 action;
    __u32 reserved;
    union {
        struct { __u64 latency_us; } fs;
        struct { __u64 latency_us; __u64 sector; __u32 device; __u32 reserved; } disk;
        struct { __u32 unit; } md;
        struct { __s32 result; __u32 result_known; } mount;
        struct { netdata_nv_idx_t key; netdata_nv_data_t data; } network;
    } details;
};

#ifdef NETDATA_STREAM_ARENA
NETDATA_ARENA_QUEUE_DECL(collector, struct netdata_stream_event_t, NETDATA_ARENA_EVENT_SLOTS);
struct netdata_collector_arena_state_t collector_arena_state __arena_global = {
    .version = NETDATA_ARENA_QUEUE_VERSION,
};
#endif

NETDATA_BPF_RINGBUF_DEF(collector_events, NETDATA_STREAM_RINGBUF_SIZE);

/* Collectors with a controller table follow the agent's apps level, like the
 * existing buffer collectors; the others report the current thread and process. */
static __always_inline struct netdata_stream_event_t __arena *netdata_stream_begin(void *ctrl, __u32 action)
{
    struct netdata_stream_event_t __arena *event =
        bpf_ringbuf_reserve(&collector_events, sizeof(*event), 0);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    __u32 tgid = 0;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = ctrl ? netdata_get_pid(ctrl, &tgid) : netdata_get_current_pid(&tgid);
    event->tgid = tgid;
    event->action = action;
    return event;
}

static __always_inline void netdata_stream_emit_call(void *ctrl, __u32 action)
{
    struct netdata_stream_event_t __arena *event = netdata_stream_begin(ctrl, action);
    if (event)
        bpf_ringbuf_submit(event, 0);
}

static __always_inline void netdata_stream_emit_fs(void *ctrl, __u32 action, __u64 latency_us)
{
    struct netdata_stream_event_t __arena *event = netdata_stream_begin(ctrl, action);
    if (!event)
        return;
    event->details.fs.latency_us = latency_us;
    bpf_ringbuf_submit(event, 0);
}

static __always_inline void netdata_stream_emit_disk(void *ctrl, __u32 device, __u64 sector, __u64 latency_us)
{
    struct netdata_stream_event_t __arena *event = netdata_stream_begin(ctrl, NETDATA_STREAM_DISK_COMPLETE);
    if (!event)
        return;
    event->details.disk.device = device;
    event->details.disk.sector = sector;
    event->details.disk.latency_us = latency_us;
    bpf_ringbuf_submit(event, 0);
}

static __always_inline void netdata_stream_emit_md(void *ctrl, __u32 unit)
{
    struct netdata_stream_event_t __arena *event = netdata_stream_begin(ctrl, NETDATA_STREAM_MD_FLUSH);
    if (!event)
        return;
    event->details.md.unit = unit;
    bpf_ringbuf_submit(event, 0);
}

static __always_inline void netdata_stream_emit_mount(void *ctrl, __u32 action, __s32 result, __u32 result_known)
{
    struct netdata_stream_event_t __arena *event = netdata_stream_begin(ctrl, action);
    if (!event)
        return;
    event->details.mount.result = result;
    event->details.mount.result_known = result_known;
    bpf_ringbuf_submit(event, 0);
}

static __always_inline void netdata_stream_emit_network(void *ctrl, __u32 action,
                                                         const netdata_nv_idx_t *key,
                                                         const netdata_nv_data_t *data)
{
    struct netdata_stream_event_t __arena *event = netdata_stream_begin(ctrl, action);
    if (!event)
        return;
    event->details.network.key = *key;
    event->details.network.data = *data;
    bpf_ringbuf_submit(event, 0);
}

#endif /* _NETDATA_STREAM_H_ */
