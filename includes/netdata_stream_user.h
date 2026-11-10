// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_STREAM_USER_H_
#define _NETDATA_STREAM_USER_H_ 1

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#define NETDATA_STREAM_ARENA_VERSION 0x4e444151U
#define NETDATA_STREAM_ARENA_SLOTS 1024U

struct netdata_stream_user_stats {
    uint64_t samples;
    uint64_t bytes;
    uint64_t dropped;
};

struct netdata_stream_user_header {
    uint32_t head;
    uint32_t tail;
    uint32_t version;
    uint32_t reserved;
    uint64_t dropped;
};

static inline int netdata_stream_arena_drain(void *base, size_t data_size,
                                             size_t page_size, size_t map_pages,
                                             struct netdata_stream_user_stats *stats)
{
    if (!base || !stats || !page_size || data_size < sizeof(struct netdata_stream_user_header))
        return -EINVAL;

    size_t map_size = map_pages * page_size;
    size_t rounded = ((data_size + page_size - 1) / page_size) * page_size;
    if (rounded > map_size)
        return -EINVAL;

    struct netdata_stream_user_header *state =
        (struct netdata_stream_user_header *)((char *)base + map_size - rounded);
    if (state->version != NETDATA_STREAM_ARENA_VERSION)
        return -EINVAL;

    size_t slots_size = data_size - sizeof(*state);
    if (slots_size % NETDATA_STREAM_ARENA_SLOTS)
        return -EINVAL;
    size_t stride = slots_size / NETDATA_STREAM_ARENA_SLOTS;
    if (stride < 8)
        return -EINVAL;

    uint32_t tail = __atomic_load_n(&state->tail, __ATOMIC_ACQUIRE);
    uint32_t head = __atomic_load_n(&state->head, __ATOMIC_ACQUIRE);
    while (tail != head) {
        if (head - tail > NETDATA_STREAM_ARENA_SLOTS)
            return -EINVAL;
        uint32_t *ready = (uint32_t *)((char *)state + sizeof(*state) +
                                       (tail % NETDATA_STREAM_ARENA_SLOTS) * stride);
        if (!__atomic_load_n(ready, __ATOMIC_ACQUIRE))
            break;
        __atomic_store_n(ready, 0, __ATOMIC_RELEASE);
        tail++;
        __atomic_store_n(&state->tail, tail, __ATOMIC_RELEASE);
        stats->samples++;
        stats->bytes += stride - 8;
    }
    stats->dropped = __atomic_load_n(&state->dropped, __ATOMIC_ACQUIRE);
    return 0;
}

#endif /* _NETDATA_STREAM_USER_H_ */
