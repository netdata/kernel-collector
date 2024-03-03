// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_NETWORK_H_
#define _NETDATA_NETWORK_H_ 1

#include <linux/in6.h>

/**
 *      SOCKET
 */

/**
 * Union used to store ip addresses
 */
union netdata_ip {
    __u8 addr8[16];
    __u16 addr16[8];
    __u32 addr32[4];
    __u64 addr64[2];
};

typedef struct netdata_socket {
    char name[TASK_COMM_LEN];

    // Timestamp
    __u64 first;        // First timestamp
    __u64 ct;           // Current timestamp
    // Socket additional info
    __u16 protocol;
    __u16 family;
    __u32 external_origin;       // We are using only lower bits, so if it is
                                 // necessary to store more info, this shoud be
                                 // split in two __u16.
    // Stats
    // Number of bytes
    struct {
        __u32 call_tcp_sent;
        __u32 call_tcp_received;
        __u64 tcp_bytes_sent;
        __u64 tcp_bytes_received;
        __u32 close;        //It is never used with UDP
        __u32 retransmit;   //It is never used with UDP
        __u32 ipv4_connect; // Use to count new connections
        __u32 ipv6_connect; // Use to count new connections
        __u32 state;        //Current socket state
    } tcp;
    // Number of calls
    struct {
        __u32 call_udp_sent; // Use to count new connections
        __u32 call_udp_received;
        __u64 udp_bytes_sent;
        __u64 udp_bytes_received;
    } udp;
} netdata_socket_t;

typedef struct netdata_bandwidth {
    __u64 first;
    __u64 ct;
    __u64 bytes_sent;
    __u64 bytes_received;
    __u64 call_tcp_sent;
    __u64 call_tcp_received;
    __u64 retransmit;
    __u64 call_udp_sent;
    __u64 call_udp_received;
    __u64 close;
    __u32 ipv4_connect;
    __u32 ipv6_connect;
} netdata_bandwidth_t;

// Index used together previous structure
typedef struct netdata_socket_idx {
    union netdata_ip saddr;
    //__u16 sport;
    union netdata_ip daddr;
    __u16 dport;
    __u32 pid;
} netdata_socket_idx_t;

typedef struct netdata_passive_connection {
    __u32 tgid;
    __u32 pid;
    __u64 counter;
} netdata_passive_connection_t;

typedef struct netdata_passive_connection_idx {
    __u16 protocol;
    __u16 port;
} netdata_passive_connection_idx_t;

enum socket_counters {
    NETDATA_KEY_CALLS_TCP_SENDMSG,
    NETDATA_KEY_ERROR_TCP_SENDMSG,
    NETDATA_KEY_BYTES_TCP_SENDMSG,

    NETDATA_KEY_CALLS_TCP_CLEANUP_RBUF,
    NETDATA_KEY_ERROR_TCP_CLEANUP_RBUF,
    NETDATA_KEY_BYTES_TCP_CLEANUP_RBUF,

    NETDATA_KEY_CALLS_TCP_CLOSE,

    NETDATA_KEY_CALLS_UDP_RECVMSG,
    NETDATA_KEY_ERROR_UDP_RECVMSG,
    NETDATA_KEY_BYTES_UDP_RECVMSG,

    NETDATA_KEY_CALLS_UDP_SENDMSG,
    NETDATA_KEY_ERROR_UDP_SENDMSG,
    NETDATA_KEY_BYTES_UDP_SENDMSG,

    NETDATA_KEY_TCP_RETRANSMIT,

    NETDATA_KEY_CALLS_TCP_CONNECT_IPV4,
    NETDATA_KEY_ERROR_TCP_CONNECT_IPV4,

    NETDATA_KEY_CALLS_TCP_CONNECT_IPV6,
    NETDATA_KEY_ERROR_TCP_CONNECT_IPV6,

    NETDATA_KEY_CALLS_TCP_SET_STATE,

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_SOCKET_COUNTER
};

enum socket_functions {
    NETDATA_FCNT_INET_CSK_ACCEPT,
    NETDATA_FCNT_TCP_RETRANSMIT,
    NETDATA_FCNT_CLEANUP_RBUF,
    NETDATA_FCNT_TCP_CLOSE,
    NETDATA_FCNT_UDP_RECEVMSG,
    NETDATA_FCNT_TCP_SENDMSG,
    NETDATA_FCNT_UDP_SENDMSG,
    NETDATA_FCNT_TCP_V4_CONNECT,
    NETDATA_FCNT_TCP_V6_CONNECT,
    NETDATA_FCNT_TCP_SET_STATE,

    NETDATA_SOCKET_FCNT_END
};

/**
 *      NETWORK VIEWER
 */

typedef enum __attribute__((packed)) {
    NETDATA_SOCKET_DIRECTION_NONE = 0,
    NETDATA_SOCKET_DIRECTION_LISTEN = (1 << 0),         // a listening socket
    NETDATA_SOCKET_DIRECTION_INBOUND = (1 << 1),        // an inbound socket connecting a remote system to a local listening socket
    NETDATA_SOCKET_DIRECTION_OUTBOUND = (1 << 2),       // a socket initiated by this system, connecting to another system
    NETDATA_SOCKET_DIRECTION_LOCAL_INBOUND = (1 << 3),  // the socket connecting 2 localhost applications
    NETDATA_SOCKET_DIRECTION_LOCAL_OUTBOUND = (1 << 4), // the socket connecting 2 localhost applications
} NETDATA_SOCKET_DIRECTION;

union ipv46 {
    uint32_t ipv4;
    struct in6_addr ipv6;
};

typedef struct netdata_nv_idx {
    union ipv46 saddr;
    __u16 sport;
    union ipv46 daddr;
    __u16 dport;
} netdata_nv_idx_t;

typedef struct netdata_nv_data {
    int state;

    __u32 pid;
    __u32 uid;
    __u64 ts;

    __u8  timer;
    __u8  retransmits;
    __u32 expires;
    __u32 rqueue;
    __u32 wqueue;

    char name[TASK_COMM_LEN];

    NETDATA_SOCKET_DIRECTION direction;

    __u16 family;
    __u16 protocol;
} netdata_nv_data_t;


#endif /* _NETDATA_NETWORK_H_ */
