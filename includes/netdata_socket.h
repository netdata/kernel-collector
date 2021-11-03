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
    __u64 recv_packets;
    __u64 sent_packets;
    __u64 recv_bytes;
    __u64 sent_bytes;
    __u64 first; //First timestamp
    __u64 ct;   //Current timestamp
    __u16 retransmit; //It is never used with UDP
    __u8 protocol;
    __u8 removeme;
    __u32 reserved;
} netdata_socket_t;

typedef struct netdata_bandwidth {
    __u32 pid;

    __u64 first;
    __u64 ct;
    __u64 bytes_sent;
    __u64 bytes_received;
    __u64 call_tcp_sent;
    __u64 call_tcp_received;
    __u64 retransmit;
    __u64 call_udp_sent;
    __u64 call_udp_received;
} netdata_bandwidth_t;

// Index used together previous structure
typedef struct netdata_socket_idx {
    union netdata_ip saddr;
    __u16 sport;
    union netdata_ip daddr;
    __u16 dport;
} netdata_socket_idx_t;

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

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_SOCKET_COUNTER
};

#endif /* _NETDATA_NETWORK_H_ */
