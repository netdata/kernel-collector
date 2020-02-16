#ifndef _NETDATA_SYSCALL_EBPF_H_
# define _NETDATA_SYSCALL_EBPF_H_ 1

# include <stdint.h>

enum netdata_map_syscall {
    FILE_SYSCALL = 0
};

typedef struct netdata_ebpf_events {
    char type;
    char *name;

} netdata_ebpf_events_t;

typedef struct netdata_latency
{
    uint64_t period;
    uint64_t counter;
}netdata_latency_t;

# define NETDATA_MAX_MONITOR_VECTOR 9

#endif
