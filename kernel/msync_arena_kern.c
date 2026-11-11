#define NETDATA_STREAM_ARENA 1
#include "netdata_arena_common.h"
#define NETDATA_BPF_RINGBUF_DEF(NAME, MAX_ENTRIES) NETDATA_BPF_ARENA_DEF(NAME, MAX_ENTRIES)
#define bpf_ringbuf_reserve(MAP, SIZE, FLAGS) netdata_collector_arena_reserve()
#define bpf_ringbuf_submit(EVENT, FLAGS) netdata_collector_arena_submit(EVENT)
#include "msync_kern.c"
