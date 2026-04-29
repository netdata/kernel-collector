// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_OOMKILL_BUFFER_H_
#define _NETDATA_OOMKILL_BUFFER_H_ 1

#define NETDATA_OOMKILL_RINGBUF_SIZE (1 << 20)

struct netdata_oomkill_event_t {
    __u64 ct;
    __u32 pid;
    __u32 pad;
};

#endif /* _NETDATA_OOMKILL_BUFFER_H_ */
