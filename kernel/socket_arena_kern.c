#define KBUILD_MODNAME "socket_arena_kern"
#include <linux/version.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_vlan.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif

#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "netdata_arena_common.h"
#include "netdata_socket_arena.h"

struct netdata_socket_arena_state_t socket_arena_state __arena_global;

#define NETDATA_BPF_RINGBUF_DEF(NAME, MAX_ENTRIES) NETDATA_BPF_ARENA_DEF(NAME, MAX_ENTRIES)
#define bpf_ringbuf_reserve(MAP, SIZE, FLAGS) netdata_socket_arena_reserve()
#define bpf_ringbuf_submit(EV, FLAGS) netdata_socket_arena_submit(EV)

#include "socket_buffer_kern.c"
