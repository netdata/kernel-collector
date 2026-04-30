// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_FD_ARENA_H_
#define _NETDATA_FD_ARENA_H_ 1

#include "netdata_fd_buffer.h"
#include "netdata_arena_common.h"

NETDATA_ARENA_QUEUE_DECL(fd, struct netdata_fd_event_t, NETDATA_ARENA_EVENT_SLOTS);

#endif /* _NETDATA_FD_ARENA_H_ */
