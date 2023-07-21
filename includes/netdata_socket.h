// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_NETWORK_H_
#define _NETDATA_NETWORK_H_ 1

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
    // Timestamp
    __u64 first;        //First timestamp
    __u64 ct;           //Current timestamp
    // Socket additional info
    __u16 protocol;
    __u16 family;
    // Stats
    // Number of bytes
    struct {
        __u32 call_tcp_sent;
        __u32 call_tcp_received;
        __u64 tcp_bytes_sent;
        __u64 tcp_bytes_received;
        __u32 close;        //It is never used with UDP
        __u32 retransmit;   //It is never used with UDP
    } tcp;
    // Number of calls
    struct {
        __u32 call_udp_sent;
        __u32 call_udp_received;
        __u64 udp_bytes_sent;
        __u64 udp_bytes_received;
    } udp;
    __u32 ipv4_connect;
    __u32 ipv6_connect;
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
    __u16 sport;
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

    NETDATA_SOCKET_FCNT_END
};

#endif /* _NETDATA_NETWORK_H_ */
