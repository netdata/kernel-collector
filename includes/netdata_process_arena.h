// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_PROCESS_ARENA_H_
#define _NETDATA_PROCESS_ARENA_H_ 1

#include "netdata_process_buffer.h"
#include "netdata_arena_common.h"

NETDATA_ARENA_QUEUE_DECL(process, struct netdata_process_event_t, NETDATA_ARENA_EVENT_SLOTS);

#endif /* _NETDATA_PROCESS_ARENA_H_ */
