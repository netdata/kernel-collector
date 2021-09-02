// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_OOMKILL_H_
#define _NETDATA_OOMKILL_H_ 1

// since we only store PIDs which are 4 bytes, and the map will be at least
// 4096 bytes, do 1024 entries.
#define NETDATA_OOMKILL_MAX_ENTRIES 1024

// /sys/kernel/debug/tracing/events/oom/mark_victim/
struct netdata_oom_mark_victim_entry {
    u64 pad;                    // This is not used with eBPF
    int pid;                    // offset:8;       size:4; signed:1;
};

#endif /* _NETDATA_OOMKILL_H_ */
