// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_ARENA_COMMON_
#define _NETDATA_ARENA_COMMON_ 1

/* Force the explicit form because the compiler form does not reliably cast
 * pointers loaded from global arena data before tracing-program accesses. */
#define NETDATA_ARENA_FORCE_ASM 1

#if defined(__BPF_FEATURE_ADDR_SPACE_CAST) && !defined(NETDATA_ARENA_FORCE_ASM)
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

/* LLVM does not consistently emit the BPF arena address-space cast when a
 * global arena object is dereferenced from a tracing program. */
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
    struct netdata_##PREFIX##_arena_state_t { \
        __u32 head; \
        EVENT_TYPE events[SLOT_COUNT]; \
    }; \
    extern __arena struct netdata_##PREFIX##_arena_state_t PREFIX##_arena_state; \
    static __always_inline __arena EVENT_TYPE *netdata_##PREFIX##_arena_reserve(void) { \
        __arena struct netdata_##PREFIX##_arena_state_t *state = &PREFIX##_arena_state; \
        netdata_bpf_addr_space_cast(state, 0, 1); \
        __u32 idx = state->head++; \
        return &state->events[idx % SLOT_COUNT]; \
    } \
    static __always_inline void netdata_##PREFIX##_arena_submit(__arena EVENT_TYPE *ev) { \
        (void)ev; \
    }

#endif /* _NETDATA_ARENA_COMMON_ */
