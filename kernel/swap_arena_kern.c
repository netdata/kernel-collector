#define KBUILD_MODNAME "swap_arena_kern"
#include <linux/version.h>
#include <linux/sched.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "netdata_arena_common.h"
#include "netdata_swap_arena.h"

struct netdata_swap_arena_state_t swap_arena_state __arena_global;

#define NETDATA_BPF_RINGBUF_DEF(NAME, MAX_ENTRIES) NETDATA_BPF_ARENA_DEF(NAME, MAX_ENTRIES)
#define bpf_ringbuf_reserve(MAP, SIZE, FLAGS) netdata_swap_arena_reserve()
#define bpf_ringbuf_submit(EV, FLAGS) netdata_swap_arena_submit(EV)

#include "swap_buffer_kern.c"
