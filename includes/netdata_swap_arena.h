// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_SWAP_ARENA_H_
#define _NETDATA_SWAP_ARENA_H_ 1

#include "netdata_swap_buffer.h"
#include "netdata_arena_common.h"

NETDATA_ARENA_QUEUE_DECL(swap, struct netdata_swap_event_t, NETDATA_ARENA_EVENT_SLOTS);

#endif /* _NETDATA_SWAP_ARENA_H_ */
