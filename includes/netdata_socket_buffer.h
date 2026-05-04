// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_SOCKET_BUFFER_H_
#define _NETDATA_SOCKET_BUFFER_H_ 1

#include "netdata_socket.h"

#define NETDATA_SOCKET_RINGBUF_SIZE (1 << 20)

struct netdata_socket_event_t {
    netdata_socket_idx_t idx;
    netdata_socket_t data;
};

#endif /* _NETDATA_SOCKET_BUFFER_H_ */
