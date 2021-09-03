// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_OOMKILL_H_
#define _NETDATA_OOMKILL_H_ 1

// to try and only use 4096 bytes in the map and no more given 4 byte keys & 1
// byte values, we choose a very small number.
#define NETDATA_OOMKILL_MAX_ENTRIES 64

// /sys/kernel/debug/tracing/events/oom/mark_victim/
struct netdata_oom_mark_victim_entry {
    u64 pad;                    // This is not used with eBPF
    int pid;                    // offset:8;       size:4; signed:1;
};

#endif /* _NETDATA_OOMKILL_H_ */
