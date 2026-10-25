// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_ARENA_COMMON_
#define _NETDATA_ARENA_COMMON_ 1

/* The native-target LLVM IR build uses an explicit BPF cast at reservation. */
#define __arena
#define __arena_global SEC(".addr_space.1")

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
/* NDAQ: reserve a bounded slot, publish it, then release it from userspace. */
#define NETDATA_ARENA_QUEUE_VERSION 0x4e444151U
#define NETDATA_ARENA_RESERVE_RETRIES 8

/* Mark the relocated userspace address as PTR_TO_ARENA before dereferencing. */
#ifndef netdata_bpf_addr_space_cast
#define netdata_bpf_addr_space_cast(var, dst_as, src_as) \
    asm volatile(\
        ".byte 0xBF; \
         .ifc %[reg], r0; .byte 0x00; .endif; \
         .ifc %[reg], r1; .byte 0x11; .endif; \
         .ifc %[reg], r2; .byte 0x22; .endif; \
         .ifc %[reg], r3; .byte 0x33; .endif; \
         .ifc %[reg], r4; .byte 0x44; .endif; \
         .ifc %[reg], r5; .byte 0x55; .endif; \
         .ifc %[reg], r6; .byte 0x66; .endif; \
         .ifc %[reg], r7; .byte 0x77; .endif; \
         .ifc %[reg], r8; .byte 0x88; .endif; \
         .ifc %[reg], r9; .byte 0x99; .endif; \
         .short %[off]; \
         .long %[as]" \
        : [reg] "+r"(var) \
        : [off] "i"(BPF_ADDR_SPACE_CAST), \
          [as] "i"(((dst_as) << 16) | (src_as)))
#endif

#define NETDATA_BPF_ARENA_DEF(NAME, MAX_ENTRIES) \
    struct { \
        __uint(type, BPF_MAP_TYPE_ARENA); \
        __uint(map_flags, BPF_F_MMAPABLE); \
        __uint(max_entries, NETDATA_ARENA_MAP_PAGES); \
        __ulong(map_extra, NETDATA_ARENA_MAP_EXTRA); \
    } NAME SEC(".maps")

#define NETDATA_ARENA_QUEUE_DECL(PREFIX, EVENT_TYPE, SLOT_COUNT) \
    struct netdata_##PREFIX##_arena_slot_t { \
        __u32 ready; \
        EVENT_TYPE event; \
    }; \
    struct netdata_##PREFIX##_arena_state_t { \
        __u32 head; \
        __u32 tail; \
        __u32 version; \
        __u32 reserved; \
        __u64 dropped; \
        struct netdata_##PREFIX##_arena_slot_t slots[SLOT_COUNT]; \
    }; \
    extern __arena struct netdata_##PREFIX##_arena_state_t PREFIX##_arena_state; \
    static __always_inline __arena EVENT_TYPE *netdata_##PREFIX##_arena_reserve(void) { \
        __arena struct netdata_##PREFIX##_arena_state_t *state = &PREFIX##_arena_state; \
        netdata_bpf_addr_space_cast(state, 0, 1); \
        for (int attempt = 0; attempt < NETDATA_ARENA_RESERVE_RETRIES; attempt++) { \
            __u32 tail = *(volatile __arena __u32 *)&state->tail; \
            __u32 head = *(volatile __arena __u32 *)&state->head; \
            if ((__s32)(head - tail) < 0) \
                continue; \
            if (head - tail >= SLOT_COUNT) { \
                __sync_fetch_and_add(&state->dropped, 1); \
                return 0; \
            } \
            if (__sync_val_compare_and_swap(&state->head, head, head + 1) == head) \
                return &state->slots[head % SLOT_COUNT].event; \
        } \
        __sync_fetch_and_add(&state->dropped, 1); \
        return 0; \
    } \
    static __always_inline void netdata_##PREFIX##_arena_submit(__arena EVENT_TYPE *ev) { \
        __arena struct netdata_##PREFIX##_arena_slot_t *slot = \
            (__arena struct netdata_##PREFIX##_arena_slot_t *) \
                ((__arena char *)ev - __builtin_offsetof(struct netdata_##PREFIX##_arena_slot_t, event)); \
        /* Every reservation must publish or the consumer cannot advance. */ \
        __sync_lock_test_and_set(&slot->ready, 1); \
    }

#endif /* _NETDATA_ARENA_COMMON_ */
