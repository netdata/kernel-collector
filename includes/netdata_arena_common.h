// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_ARENA_COMMON_
#define _NETDATA_ARENA_COMMON_ 1

#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
#define __arena __attribute__((address_space(1)))
#define __arena_global __attribute__((address_space(1)))
#else
#define __arena
#define __arena_global SEC(".addr_space.1")
#endif

#ifndef __arg_arena
#define __arg_arena __attribute__((btf_decl_tag("arg:arena")))
#endif

#if defined(__TARGET_ARCH_arm64)
#define NETDATA_ARENA_MAP_EXTRA (0x1ull << 32)
#else
#define NETDATA_ARENA_MAP_EXTRA (0x1ull << 44)
#endif

#define NETDATA_ARENA_MAP_PAGES 256
#define NETDATA_ARENA_EVENT_SLOTS 1024

#define NETDATA_BPF_ARENA_DEF(NAME, MAX_ENTRIES) \
    struct { \
        __uint(type, BPF_MAP_TYPE_ARENA); \
        __uint(map_flags, BPF_F_MMAPABLE); \
        __uint(max_entries, NETDATA_ARENA_MAP_PAGES); \
        __ulong(map_extra, NETDATA_ARENA_MAP_EXTRA); \
    } NAME SEC(".maps")

#define NETDATA_ARENA_QUEUE_DECL(PREFIX, EVENT_TYPE, SLOT_COUNT) \
    struct netdata_##PREFIX##_arena_state_t { \
        __u32 head; \
        EVENT_TYPE events[SLOT_COUNT]; \
    }; \
    extern __arena struct netdata_##PREFIX##_arena_state_t PREFIX##_arena_state; \
    static __always_inline __arena EVENT_TYPE *netdata_##PREFIX##_arena_reserve(void) { \
        /* BPF backend rejects using the XADD return value directly. */ \
        __sync_fetch_and_add(&PREFIX##_arena_state.head, 1); \
        __u32 idx = PREFIX##_arena_state.head - 1; \
        return &PREFIX##_arena_state.events[idx % SLOT_COUNT]; \
    } \
    static __always_inline void netdata_##PREFIX##_arena_submit(__arena EVENT_TYPE *ev) { \
        (void)ev; \
    }

#endif /* _NETDATA_ARENA_COMMON_ */
