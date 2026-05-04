#include <arpa/inet.h>
#include <bpf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libbpf.h>

#include "tester_socket.h"

/*
 * Binary layout of netdata_socket_idx_t (40 bytes).
 * Offsets must match kernel struct in includes/netdata_socket.h.
 */
#define SOCKET_IDX_SADDR_OFFSET  0    /* union netdata_ip: 16 bytes */
#define SOCKET_IDX_DADDR_OFFSET  16   /* union netdata_ip: 16 bytes */
#define SOCKET_IDX_DPORT_OFFSET  32   /* __u16: 2 bytes             */
#define SOCKET_IDX_PID_OFFSET    36   /* __u32: 4 bytes (after 2B pad) */
#define SOCKET_IDX_SIZE          40

/*
 * Binary layout of netdata_socket_t (112 bytes).
 * Offsets must match kernel struct in includes/netdata_socket.h.
 */
#define SOCKET_VAL_NAME_OFFSET         0    /* char[16]  */
#define SOCKET_VAL_FIRST_OFFSET        16   /* __u64     */
#define SOCKET_VAL_CT_OFFSET           24   /* __u64     */
#define SOCKET_VAL_PROTOCOL_OFFSET     32   /* __u16     */
#define SOCKET_VAL_FAMILY_OFFSET       34   /* __u16     */
#define SOCKET_VAL_EXTORIGIN_OFFSET    36   /* __u32     */
/* tcp sub-struct starts at offset 40 */
#define SOCKET_VAL_TCP_SENT_CALLS      40   /* __u32 */
#define SOCKET_VAL_TCP_RECV_CALLS      44   /* __u32 */
#define SOCKET_VAL_TCP_BYTES_SENT      48   /* __u64 */
#define SOCKET_VAL_TCP_BYTES_RECV      56   /* __u64 */
#define SOCKET_VAL_TCP_CLOSE           64   /* __u32 */
#define SOCKET_VAL_TCP_RETRANSMIT      68   /* __u32 */
#define SOCKET_VAL_TCP_IPV4_CONNECT    72   /* __u32 */
#define SOCKET_VAL_TCP_IPV6_CONNECT    76   /* __u32 */
#define SOCKET_VAL_TCP_STATE           80   /* __u32 */
/* 4 bytes implicit padding at 84 to align udp to 8-byte boundary */
/* udp sub-struct starts at offset 88 */
#define SOCKET_VAL_UDP_SENT_CALLS      88   /* __u32 */
#define SOCKET_VAL_UDP_RECV_CALLS      92   /* __u32 */
#define SOCKET_VAL_UDP_BYTES_SENT      96   /* __u64 */
#define SOCKET_VAL_UDP_BYTES_RECV      104  /* __u64 */
#define SOCKET_VAL_SIZE                112

#define SOCKET_NAME_LEN  16
#define SOCKET_SLEEP_SEC 5

/* -------------------------------------------------------------------------
 * Low-level read helpers (little-endian, same as the kernel writes them).
 * -------------------------------------------------------------------------*/

static uint16_t sock_read_u16(const uint8_t *src)
{
    uint16_t v;
    memcpy(&v, src, sizeof(v));
    return v;
}

static uint32_t sock_read_u32(const uint8_t *src)
{
    uint32_t v;
    memcpy(&v, src, sizeof(v));
    return v;
}

static uint64_t sock_read_u64(const uint8_t *src)
{
    uint64_t v;
    memcpy(&v, src, sizeof(v));
    return v;
}

/* -------------------------------------------------------------------------
 * Decoded, aggregated representation of one connection entry.
 * -------------------------------------------------------------------------*/

typedef struct {
    uint8_t  saddr[16];
    uint8_t  daddr[16];
    uint16_t dport;
    uint32_t pid;
    char     name[SOCKET_NAME_LEN + 1];
    uint16_t protocol;
    uint16_t family;

    uint32_t tcp_sent_calls;
    uint32_t tcp_recv_calls;
    uint64_t tcp_bytes_sent;
    uint64_t tcp_bytes_recv;
    uint32_t tcp_close;
    uint32_t tcp_retransmit;
    uint32_t tcp_ipv4_connect;
    uint32_t tcp_ipv6_connect;
    uint32_t tcp_state;

    uint32_t udp_sent_calls;
    uint32_t udp_recv_calls;
    uint64_t udp_bytes_sent;
    uint64_t udp_bytes_recv;
} socket_entry_t;

static void socket_decode_key(socket_entry_t *e, const uint8_t *key)
{
    memcpy(e->saddr, key + SOCKET_IDX_SADDR_OFFSET, 16);
    memcpy(e->daddr, key + SOCKET_IDX_DADDR_OFFSET, 16);
    e->dport = sock_read_u16(key + SOCKET_IDX_DPORT_OFFSET);
    e->pid   = sock_read_u32(key + SOCKET_IDX_PID_OFFSET);
}

/*
 * Aggregate ncpus per-CPU slots (each 'stride' bytes apart) into one entry.
 * Non-name scalar fields are summed; name and family come from the first
 * non-empty CPU slot encountered.
 */
static void socket_aggregate_percpu(socket_entry_t *e, const uint8_t *buf,
                                    size_t stride, int ncpus)
{
    int cpu;
    int meta_found = 0;

    memset(e->name, 0, sizeof(e->name));
    e->protocol = 0;
    e->family   = 0;
    e->tcp_sent_calls = e->tcp_recv_calls = 0;
    e->tcp_bytes_sent = e->tcp_bytes_recv = 0;
    e->tcp_close = e->tcp_retransmit = 0;
    e->tcp_ipv4_connect = e->tcp_ipv6_connect = 0;
    e->tcp_state = 0;
    e->udp_sent_calls = e->udp_recv_calls = 0;
    e->udp_bytes_sent = e->udp_bytes_recv = 0;

    for (cpu = 0; cpu < ncpus; cpu++) {
        const uint8_t *slot = buf + (size_t)cpu * stride;

        if (!meta_found && slot[SOCKET_VAL_NAME_OFFSET] != '\0') {
            memcpy(e->name, slot + SOCKET_VAL_NAME_OFFSET, SOCKET_NAME_LEN);
            e->name[SOCKET_NAME_LEN] = '\0';
            e->protocol = sock_read_u16(slot + SOCKET_VAL_PROTOCOL_OFFSET);
            e->family   = sock_read_u16(slot + SOCKET_VAL_FAMILY_OFFSET);
            meta_found  = 1;
        }

        e->tcp_sent_calls   += sock_read_u32(slot + SOCKET_VAL_TCP_SENT_CALLS);
        e->tcp_recv_calls   += sock_read_u32(slot + SOCKET_VAL_TCP_RECV_CALLS);
        e->tcp_bytes_sent   += sock_read_u64(slot + SOCKET_VAL_TCP_BYTES_SENT);
        e->tcp_bytes_recv   += sock_read_u64(slot + SOCKET_VAL_TCP_BYTES_RECV);
        e->tcp_close        += sock_read_u32(slot + SOCKET_VAL_TCP_CLOSE);
        e->tcp_retransmit   += sock_read_u32(slot + SOCKET_VAL_TCP_RETRANSMIT);
        e->tcp_ipv4_connect += sock_read_u32(slot + SOCKET_VAL_TCP_IPV4_CONNECT);
        e->tcp_ipv6_connect += sock_read_u32(slot + SOCKET_VAL_TCP_IPV6_CONNECT);
        e->udp_sent_calls   += sock_read_u32(slot + SOCKET_VAL_UDP_SENT_CALLS);
        e->udp_recv_calls   += sock_read_u32(slot + SOCKET_VAL_UDP_RECV_CALLS);
        e->udp_bytes_sent   += sock_read_u64(slot + SOCKET_VAL_UDP_BYTES_SENT);
        e->udp_bytes_recv   += sock_read_u64(slot + SOCKET_VAL_UDP_BYTES_RECV);

        {
            uint32_t st = sock_read_u32(slot + SOCKET_VAL_TCP_STATE);
            if (st)
                e->tcp_state = st;
        }
    }
}

static void socket_format_ip(char *buf, size_t buflen, const uint8_t *raw, uint16_t family)
{
    if (family == AF_INET6)
        inet_ntop(AF_INET6, raw, buf, (socklen_t)buflen);
    else
        inet_ntop(AF_INET, raw, buf, (socklen_t)buflen);
}

/*
 * Escape a process name string for JSON.  Process names (TASK_COMM_LEN) are
 * ASCII, but we handle the two characters that would break JSON strings.
 */
static void socket_write_json_name(FILE *out, const char *name)
{
    const char *p;
    fputc('"', out);
    for (p = name; *p; p++) {
        if (*p == '"')
            fputs("\\\"", out);
        else if (*p == '\\')
            fputs("\\\\", out);
        else
            fputc(*p, out);
    }
    fputc('"', out);
}

static void socket_write_entry_json(FILE *out, const socket_entry_t *e)
{
    char src_buf[INET6_ADDRSTRLEN];
    char dst_buf[INET6_ADDRSTRLEN];

    src_buf[0] = dst_buf[0] = '\0';
    socket_format_ip(src_buf, sizeof(src_buf), e->saddr, e->family);
    socket_format_ip(dst_buf, sizeof(dst_buf), e->daddr, e->family);

    fprintf(out,
            "                                    "
            "{ \"src_ip\" : \"%s\", \"dst_ip\" : \"%s\", "
            "\"dst_port\" : %u, \"pid\" : %u, \"name\" : ",
            src_buf, dst_buf,
            (unsigned)e->dport, (unsigned)e->pid);
    socket_write_json_name(out, e->name);
    fprintf(out,
            ", \"protocol\" : %u, \"family\" : %u, "
            "\"tcp\" : { \"sent_calls\" : %u, \"recv_calls\" : %u, "
            "\"bytes_sent\" : %llu, \"bytes_recv\" : %llu, "
            "\"close\" : %u, \"retransmit\" : %u, "
            "\"ipv4_connect\" : %u, \"ipv6_connect\" : %u, "
            "\"state\" : %u }, "
            "\"udp\" : { \"sent_calls\" : %u, \"recv_calls\" : %u, "
            "\"bytes_sent\" : %llu, \"bytes_recv\" : %llu } }",
            (unsigned)e->protocol, (unsigned)e->family,
            (unsigned)e->tcp_sent_calls, (unsigned)e->tcp_recv_calls,
            (unsigned long long)e->tcp_bytes_sent,
            (unsigned long long)e->tcp_bytes_recv,
            (unsigned)e->tcp_close, (unsigned)e->tcp_retransmit,
            (unsigned)e->tcp_ipv4_connect, (unsigned)e->tcp_ipv6_connect,
            (unsigned)e->tcp_state,
            (unsigned)e->udp_sent_calls, (unsigned)e->udp_recv_calls,
            (unsigned long long)e->udp_bytes_sent,
            (unsigned long long)e->udp_bytes_recv);
}

/* -------------------------------------------------------------------------
 * Public interface.
 * -------------------------------------------------------------------------*/

int ebpf_object_has_socket_table(struct bpf_object *obj)
{
    struct bpf_map *map;

    bpf_object__for_each_map(map, obj) {
        if (!strcmp(bpf_map__name(map), "tbl_nd_socket"))
            return 1;
    }

    return 0;
}

void ebpf_socket_table_tester(struct bpf_object *obj, FILE *out, int iterations)
{
    struct bpf_map *map = NULL;
    struct bpf_map *m;
    int fd;
    uint32_t key_size, value_size, map_type;
    int ncpus;
    size_t stride;
    uint8_t *key_buf     = NULL;
    uint8_t *next_key    = NULL;
    uint8_t *percpu_buf  = NULL;
    int entry_count = 0;
    int first       = 1;
    int collection_seconds = iterations * SOCKET_SLEEP_SEC;

    bpf_object__for_each_map(m, obj) {
        if (!strcmp(bpf_map__name(m), "tbl_nd_socket")) {
            map = m;
            break;
        }
    }

    if (!map) {
        fprintf(out, "        \"Total tables\" : 0\n");
        return;
    }

    fd         = bpf_map__fd(map);
#ifdef LIBBPF_MAJOR_VERSION
    map_type   = (uint32_t)bpf_map__type(map);
    key_size   = bpf_map__key_size(map);
    value_size = bpf_map__value_size(map);
#else
    {
        const struct bpf_map_def *def = bpf_map__def(map);
        map_type   = (uint32_t)def->type;
        key_size   = def->key_size;
        value_size = def->value_size;
    }
#endif

    ncpus  = libbpf_num_possible_cpus();
    if (ncpus <= 0)
        ncpus = 1;

    /* PERCPU_HASH: each lookup returns ncpus * stride bytes. */
    stride = ((size_t)value_size + 7U) & ~7U; /* round up to 8-byte boundary */

    key_buf    = calloc(key_size, 1);
    next_key   = calloc(key_size, 1);
    percpu_buf = calloc((size_t)ncpus * stride, 1);
    if (!key_buf || !next_key || !percpu_buf)
        goto cleanup;

    fprintf(out,
            "        \"socket_connections\" : {\n"
            "            \"Info\" : { \"Length\" : { \"Key\" : %u, \"Value\" : %u},\n"
            "                       \"Type\" : %u,\n"
            "                       \"FD\" : %d,\n"
            "                       \"ncpus\" : %d,\n"
            "                       \"Collection Seconds\" : %d,\n"
            "                       \"Data\" : [\n",
            key_size, value_size, map_type, fd, ncpus, collection_seconds);

    sleep((unsigned int)collection_seconds);

    if (bpf_map_get_next_key(fd, NULL, next_key))
        goto write_footer;

    do {
        socket_entry_t entry;

        if (bpf_map_lookup_elem(fd, next_key, percpu_buf))
            goto advance;

        socket_decode_key(&entry, next_key);
        socket_aggregate_percpu(&entry, percpu_buf, stride, ncpus);

        if (!first)
            fprintf(out, ",\n");

        socket_write_entry_json(out, &entry);
        first = 0;
        entry_count++;

advance:
        memcpy(key_buf, next_key, key_size);
    } while (!bpf_map_get_next_key(fd, key_buf, next_key));

write_footer:
    if (!first)
        fprintf(out, "\n");

    fprintf(out,
            "                                ]\n"
            "                      }\n"
            "        },\n"
            "        \"Total tables\" : 1\n");

cleanup:
    free(key_buf);
    free(next_key);
    free(percpu_buf);
}
