// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_DC_ARENA_H_
#define _NETDATA_DC_ARENA_H_ 1

#include "netdata_dc_buffer.h"
#include "netdata_arena_common.h"

NETDATA_ARENA_QUEUE_DECL(dc, struct netdata_dc_event_t, NETDATA_ARENA_EVENT_SLOTS);

#endif /* _NETDATA_DC_ARENA_H_ */
