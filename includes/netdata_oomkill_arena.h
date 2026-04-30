// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_OOMKILL_ARENA_H_
#define _NETDATA_OOMKILL_ARENA_H_ 1

#include "netdata_oomkill_buffer.h"
#include "netdata_arena_common.h"

NETDATA_ARENA_QUEUE_DECL(oomkill, struct netdata_oomkill_event_t, NETDATA_ARENA_EVENT_SLOTS);

#endif /* _NETDATA_OOMKILL_ARENA_H_ */
