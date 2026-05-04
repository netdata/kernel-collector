#define KBUILD_MODNAME "oomkill_arena_kern"
#include <linux/ptrace.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "netdata_arena_common.h"
#include "netdata_oomkill_arena.h"

struct netdata_oomkill_arena_state_t oomkill_arena_state __arena_global;

#define NETDATA_BPF_RINGBUF_DEF(NAME, MAX_ENTRIES) NETDATA_BPF_ARENA_DEF(NAME, MAX_ENTRIES)
#define bpf_ringbuf_reserve(MAP, SIZE, FLAGS) netdata_oomkill_arena_reserve()
#define bpf_ringbuf_submit(EV, FLAGS) netdata_oomkill_arena_submit(EV)

#include "oomkill_buffer_kern.c"
