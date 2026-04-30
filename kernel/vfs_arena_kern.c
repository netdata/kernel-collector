#define KBUILD_MODNAME "vfs_arena_kern"
#include <linux/version.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,10,17))
# include <linux/sched/task.h>
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "netdata_arena_common.h"
#include "netdata_vfs_arena.h"

struct netdata_vfs_arena_state_t vfs_arena_state __arena_global;

#define NETDATA_BPF_RINGBUF_DEF(NAME, MAX_ENTRIES) NETDATA_BPF_ARENA_DEF(NAME, MAX_ENTRIES)
#define bpf_ringbuf_reserve(MAP, SIZE, FLAGS) netdata_vfs_arena_reserve()
#define bpf_ringbuf_submit(EV, FLAGS) netdata_vfs_arena_submit(EV)

#include "vfs_buffer_kern.c"
