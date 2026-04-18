#include <arpa/inet.h>
#include <bpf.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <libbpf.h>

#include "tester_dns.h"

#define NETDATA_DNS_CAPTURE_INTERVAL 5
#define NETDATA_DNS_TIMEOUT_USEC (5ULL * 1000000ULL)
#define NETDATA_DNS_MAX_DOMAIN_LENGTH 256
#define NETDATA_DNS_PACKET_BUFFER 65536
#define NETDATA_DNS_IPV4_MIN_HEADER 20
#define NETDATA_DNS_IPV6_HEADER 40
#define NETDATA_DNS_UDP_HEADER 8
#define NETDATA_DNS_TCP_MIN_HEADER 20

typedef struct netdata_dns_flow_key {
    uint8_t family;
    uint8_t protocol;
    uint16_t client_port;
    uint8_t server_ip[16];
    uint8_t client_ip[16];
} netdata_dns_flow_key_t;

typedef struct netdata_dns_rcode_counter {
    uint32_t code;
    uint32_t count;
    struct netdata_dns_rcode_counter *next;
} netdata_dns_rcode_counter_t;

typedef struct netdata_dns_stats {
    netdata_dns_flow_key_t key;
    uint16_t query_type;
    char domain[NETDATA_DNS_MAX_DOMAIN_LENGTH];
    uint32_t timeouts;
    uint64_t success_latency_sum;
    uint64_t failure_latency_sum;
    netdata_dns_rcode_counter_t *rcodes;
    struct netdata_dns_stats *next;
} netdata_dns_stats_t;

typedef struct netdata_dns_state {
    netdata_dns_flow_key_t key;
    uint16_t transaction_id;
    uint16_t query_type;
    uint64_t timestamp_usec;
    char domain[NETDATA_DNS_MAX_DOMAIN_LENGTH];
    struct netdata_dns_state *next;
} netdata_dns_state_t;

typedef struct netdata_dns_collector {
    netdata_dns_stats_t *stats;
    netdata_dns_state_t *state;
    size_t pending_queries;
    size_t total_results;
} netdata_dns_collector_t;

typedef struct netdata_dns_packet {
    netdata_dns_flow_key_t key;
    uint16_t transaction_id;
    uint16_t query_type;
    uint8_t response;
    uint8_t rcode;
    char domain[NETDATA_DNS_MAX_DOMAIN_LENGTH];
} netdata_dns_packet_t;

static uint16_t dns_read_u16(const uint8_t *src)
{
    return ((uint16_t)src[0] << 8) | src[1];
}

static uint64_t dns_now_usec(void)
{
    struct timespec ts = { };

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return ((uint64_t)ts.tv_sec * 1000000ULL) + ((uint64_t)ts.tv_nsec / 1000ULL);
}

static size_t dns_ip_size(uint8_t family)
{
    return (family == AF_INET6) ? 16 : 4;
}

static int dns_flow_key_equal(const netdata_dns_flow_key_t *a, const netdata_dns_flow_key_t *b)
{
    size_t length;

    if (a->family != b->family || a->protocol != b->protocol || a->client_port != b->client_port)
        return 0;

    length = dns_ip_size(a->family);
    if (memcmp(a->server_ip, b->server_ip, length))
        return 0;

    if (memcmp(a->client_ip, b->client_ip, length))
        return 0;

    return 1;
}

static void dns_format_ip(char *dst, size_t len, uint8_t family, const uint8_t *src)
{
    if (!inet_ntop(family, src, dst, len))
        snprintf(dst, len, "invalid");
}

static int dns_read_name(const uint8_t *data, size_t length, size_t offset, char *dst, size_t dst_len, size_t *next)
{
    size_t current = offset;
    size_t out = 0;
    size_t jumps = 0;
    int jumped = 0;

    if (!dst_len)
        return 0;

    while (current < length && jumps < 32) {
        uint8_t label = data[current];

        if ((label & 0xC0) == 0xC0) {
            size_t pointer;

            if (current + 1 >= length)
                return 0;

            pointer = ((size_t)(label & 0x3F) << 8) | data[current + 1];
            if (!jumped) {
                *next = current + 2;
                jumped = 1;
            }

            current = pointer;
            jumps++;
            continue;
        }

        current++;
        if (label == 0) {
            if (!jumped)
                *next = current;

            if (!out) {
                if (dst_len < 2)
                    return 0;

                dst[0] = '.';
                dst[1] = '\0';
            } else {
                dst[out] = '\0';
            }

            return 1;
        }

        if (label > 63 || current + label > length)
            return 0;

        if (out && out + 1 >= dst_len)
            return 0;

        if (out)
            dst[out++] = '.';

        if (out + label >= dst_len)
            return 0;

        while (label--) {
            unsigned char ch = data[current++];

            if (ch >= 'A' && ch <= 'Z')
                ch = (unsigned char)(ch - 'A' + 'a');

            dst[out++] = (char)ch;
        }

        jumps++;
    }

    return 0;
}

static int dns_parse_payload(const uint8_t *payload, size_t payload_len, uint8_t protocol, netdata_dns_packet_t *packet)
{
    const uint8_t *message = payload;
    size_t message_len = payload_len;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t qclass;
    size_t offset = 12;

    if (protocol == IPPROTO_TCP) {
        uint16_t dns_length;

        if (payload_len < 2)
            return 0;

        dns_length = dns_read_u16(payload);
        if (!dns_length || (size_t)dns_length + 2 > payload_len)
            return 0;

        message = payload + 2;
        message_len = dns_length;
    }

    if (message_len < 12)
        return 0;

    packet->transaction_id = dns_read_u16(message);
    flags = dns_read_u16(message + 2);
    qdcount = dns_read_u16(message + 4);

    if (qdcount != 1)
        return 0;

    if (!dns_read_name(message, message_len, offset, packet->domain, sizeof(packet->domain), &offset))
        return 0;

    if (offset + 4 > message_len)
        return 0;

    packet->query_type = dns_read_u16(message + offset);
    qclass = dns_read_u16(message + offset + 2);
    if (qclass != 1)
        return 0;

    packet->response = (flags & 0x8000U) ? 1 : 0;
    packet->rcode = (uint8_t)(flags & 0x000FU);

    return 1;
}

static int dns_parse_ipv4(const uint8_t *packet, size_t length, size_t offset, netdata_dns_packet_t *dns_packet)
{
    size_t ihl;
    size_t l4_offset;
    size_t l4_length;
    uint16_t total_length;
    uint16_t frag_off;
    uint8_t protocol;
    uint16_t src_port;
    uint16_t dst_port;
    const uint8_t *payload;
    size_t payload_length;

    if (offset + NETDATA_DNS_IPV4_MIN_HEADER > length)
        return 0;

    if ((packet[offset] >> 4) != 4)
        return 0;

    ihl = (packet[offset] & 0x0FU) * 4U;
    if (ihl < NETDATA_DNS_IPV4_MIN_HEADER || offset + ihl > length)
        return 0;

    total_length = dns_read_u16(packet + offset + 2);
    if (total_length < ihl)
        return 0;

    frag_off = dns_read_u16(packet + offset + 6);
    if (frag_off & 0x1FFFU)
        return 0;

    protocol = packet[offset + 9];
    if (protocol != IPPROTO_UDP && protocol != IPPROTO_TCP)
        return 0;

    l4_offset = offset + ihl;
    if (offset + total_length < l4_offset)
        return 0;

    l4_length = (offset + total_length <= length) ? (offset + total_length - l4_offset) : (length - l4_offset);
    if (!l4_length)
        return 0;

    if (protocol == IPPROTO_UDP) {
        if (l4_length < NETDATA_DNS_UDP_HEADER)
            return 0;

        src_port = dns_read_u16(packet + l4_offset);
        dst_port = dns_read_u16(packet + l4_offset + 2);
        payload = packet + l4_offset + NETDATA_DNS_UDP_HEADER;
        payload_length = l4_length - NETDATA_DNS_UDP_HEADER;
    } else {
        size_t tcp_header_length;

        if (l4_length < NETDATA_DNS_TCP_MIN_HEADER)
            return 0;

        src_port = dns_read_u16(packet + l4_offset);
        dst_port = dns_read_u16(packet + l4_offset + 2);
        tcp_header_length = (size_t)((packet[l4_offset + 12] >> 4) & 0x0FU) * 4U;
        if (tcp_header_length < NETDATA_DNS_TCP_MIN_HEADER || tcp_header_length > l4_length)
            return 0;

        payload = packet + l4_offset + tcp_header_length;
        payload_length = l4_length - tcp_header_length;
    }

    memset(dns_packet, 0, sizeof(*dns_packet));
    if (!dns_parse_payload(payload, payload_length, protocol, dns_packet))
        return 0;

    dns_packet->key.family = AF_INET;
    dns_packet->key.protocol = protocol;
    if (!dns_packet->response) {
        memcpy(dns_packet->key.client_ip, packet + offset + 12, 4);
        memcpy(dns_packet->key.server_ip, packet + offset + 16, 4);
        dns_packet->key.client_port = src_port;
    } else {
        memcpy(dns_packet->key.server_ip, packet + offset + 12, 4);
        memcpy(dns_packet->key.client_ip, packet + offset + 16, 4);
        dns_packet->key.client_port = dst_port;
    }

    return 1;
}

static int dns_parse_ipv6(const uint8_t *packet, size_t length, size_t offset, netdata_dns_packet_t *dns_packet)
{
    size_t l4_offset;
    size_t l4_length;
    uint16_t payload_size;
    uint8_t protocol;
    uint16_t src_port;
    uint16_t dst_port;
    const uint8_t *payload;
    size_t payload_length;

    if (offset + NETDATA_DNS_IPV6_HEADER > length)
        return 0;

    if ((packet[offset] >> 4) != 6)
        return 0;

    payload_size = dns_read_u16(packet + offset + 4);
    protocol = packet[offset + 6];
    if (protocol != IPPROTO_UDP && protocol != IPPROTO_TCP)
        return 0;

    l4_offset = offset + NETDATA_DNS_IPV6_HEADER;
    if (l4_offset > length)
        return 0;

    l4_length = (l4_offset + payload_size <= length) ? payload_size : (length - l4_offset);
    if (!l4_length)
        return 0;

    if (protocol == IPPROTO_UDP) {
        if (l4_length < NETDATA_DNS_UDP_HEADER)
            return 0;

        src_port = dns_read_u16(packet + l4_offset);
        dst_port = dns_read_u16(packet + l4_offset + 2);
        payload = packet + l4_offset + NETDATA_DNS_UDP_HEADER;
        payload_length = l4_length - NETDATA_DNS_UDP_HEADER;
    } else {
        size_t tcp_header_length;

        if (l4_length < NETDATA_DNS_TCP_MIN_HEADER)
            return 0;

        src_port = dns_read_u16(packet + l4_offset);
        dst_port = dns_read_u16(packet + l4_offset + 2);
        tcp_header_length = (size_t)((packet[l4_offset + 12] >> 4) & 0x0FU) * 4U;
        if (tcp_header_length < NETDATA_DNS_TCP_MIN_HEADER || tcp_header_length > l4_length)
            return 0;

        payload = packet + l4_offset + tcp_header_length;
        payload_length = l4_length - tcp_header_length;
    }

    memset(dns_packet, 0, sizeof(*dns_packet));
    if (!dns_parse_payload(payload, payload_length, protocol, dns_packet))
        return 0;

    dns_packet->key.family = AF_INET6;
    dns_packet->key.protocol = protocol;
    if (!dns_packet->response) {
        memcpy(dns_packet->key.client_ip, packet + offset + 8, 16);
        memcpy(dns_packet->key.server_ip, packet + offset + 24, 16);
        dns_packet->key.client_port = src_port;
    } else {
        memcpy(dns_packet->key.server_ip, packet + offset + 8, 16);
        memcpy(dns_packet->key.client_ip, packet + offset + 24, 16);
        dns_packet->key.client_port = dst_port;
    }

    return 1;
}

static int dns_parse_packet(const uint8_t *packet, size_t length, netdata_dns_packet_t *dns_packet)
{
    size_t offset = ETH_HLEN;
    uint16_t protocol;

    if (length < ETH_HLEN)
        return 0;

    protocol = dns_read_u16(packet + 12);
    while (protocol == ETH_P_8021Q || protocol == ETH_P_8021AD) {
        if (offset + 4 > length)
            return 0;

        protocol = dns_read_u16(packet + offset + 2);
        offset += 4;
    }

    if (protocol == ETH_P_IP)
        return dns_parse_ipv4(packet, length, offset, dns_packet);

    if (protocol == ETH_P_IPV6)
        return dns_parse_ipv6(packet, length, offset, dns_packet);

    return 0;
}

static netdata_dns_stats_t *dns_find_stats(netdata_dns_collector_t *collector, const netdata_dns_flow_key_t *key,
                                           const char *domain, uint16_t query_type)
{
    netdata_dns_stats_t *current = collector->stats;

    while (current) {
        if (current->query_type == query_type && !strcmp(current->domain, domain) && dns_flow_key_equal(&current->key, key))
            return current;

        current = current->next;
    }

    return NULL;
}

static netdata_dns_stats_t *dns_get_stats(netdata_dns_collector_t *collector, const netdata_dns_flow_key_t *key,
                                          const char *domain, uint16_t query_type)
{
    netdata_dns_stats_t *stats = dns_find_stats(collector, key, domain, query_type);

    if (stats)
        return stats;

    stats = calloc(1, sizeof(*stats));
    if (!stats)
        return NULL;

    memcpy(&stats->key, key, sizeof(*key));
    stats->query_type = query_type;
    strncpy(stats->domain, domain, sizeof(stats->domain) - 1);
    stats->next = collector->stats;
    collector->stats = stats;
    collector->total_results++;

    return stats;
}

static void dns_increment_rcode(netdata_dns_stats_t *stats, uint8_t rcode)
{
    netdata_dns_rcode_counter_t *current = stats->rcodes;

    while (current) {
        if (current->code == rcode) {
            current->count++;
            return;
        }

        current = current->next;
    }

    current = calloc(1, sizeof(*current));
    if (!current)
        return;

    current->code = rcode;
    current->count = 1;
    current->next = stats->rcodes;
    stats->rcodes = current;
}

static void dns_timeout_state(netdata_dns_collector_t *collector, netdata_dns_state_t *state)
{
    netdata_dns_stats_t *stats = dns_get_stats(collector, &state->key, state->domain, state->query_type);

    if (stats)
        stats->timeouts++;
}

static void dns_expire_states(netdata_dns_collector_t *collector, uint64_t now_usec)
{
    netdata_dns_state_t **current = &collector->state;

    while (*current) {
        netdata_dns_state_t *state = *current;

        if (now_usec - state->timestamp_usec > NETDATA_DNS_TIMEOUT_USEC) {
            dns_timeout_state(collector, state);
            *current = state->next;
            free(state);
            collector->pending_queries--;
            continue;
        }

        current = &state->next;
    }
}

static void dns_process_query(netdata_dns_collector_t *collector, const netdata_dns_packet_t *packet, uint64_t now_usec)
{
    netdata_dns_state_t *current = collector->state;

    while (current) {
        if (current->transaction_id == packet->transaction_id && dns_flow_key_equal(&current->key, &packet->key))
            return;

        current = current->next;
    }

    current = calloc(1, sizeof(*current));
    if (!current)
        return;

    memcpy(&current->key, &packet->key, sizeof(packet->key));
    current->transaction_id = packet->transaction_id;
    current->query_type = packet->query_type;
    current->timestamp_usec = now_usec;
    strncpy(current->domain, packet->domain, sizeof(current->domain) - 1);
    current->next = collector->state;
    collector->state = current;
    collector->pending_queries++;
}

static void dns_process_response(netdata_dns_collector_t *collector, const netdata_dns_packet_t *packet, uint64_t now_usec)
{
    netdata_dns_state_t **current = &collector->state;

    while (*current) {
        netdata_dns_state_t *state = *current;

        if (state->transaction_id == packet->transaction_id && dns_flow_key_equal(&state->key, &packet->key)) {
            uint64_t latency = now_usec - state->timestamp_usec;
            netdata_dns_stats_t *stats = dns_get_stats(collector, &state->key, state->domain, state->query_type);

            if (stats) {
                if (latency > NETDATA_DNS_TIMEOUT_USEC) {
                    stats->timeouts++;
                } else {
                    dns_increment_rcode(stats, packet->rcode);
                    if (packet->rcode == 0)
                        stats->success_latency_sum += latency;
                    else
                        stats->failure_latency_sum += latency;
                }
            }

            *current = state->next;
            free(state);
            collector->pending_queries--;
            return;
        }

        current = &state->next;
    }
}

static void dns_free_collector(netdata_dns_collector_t *collector)
{
    netdata_dns_state_t *state = collector->state;
    netdata_dns_stats_t *stats = collector->stats;

    while (state) {
        netdata_dns_state_t *next = state->next;

        free(state);
        state = next;
    }

    while (stats) {
        netdata_dns_rcode_counter_t *rcode = stats->rcodes;
        netdata_dns_stats_t *next = stats->next;

        while (rcode) {
            netdata_dns_rcode_counter_t *rcode_next = rcode->next;

            free(rcode);
            rcode = rcode_next;
        }

        free(stats);
        stats = next;
    }
}

static void dns_write_ports_json(FILE *stdlog, struct bpf_object *obj, const uint16_t *ports, size_t port_count)
{
    struct bpf_map *map;
    const char *name = "dns_ports";

    bpf_object__for_each_map(map, obj) {
        const char *map_name = bpf_map__name(map);
        uint32_t key_size;
        uint32_t value_size;
        uint32_t max_entries;
        int fd;
        int type;
        size_t i;

        if (strcmp(map_name, name))
            continue;

        fd = bpf_map__fd(map);
#ifdef LIBBPF_MAJOR_VERSION
        type = bpf_map__type(map);
        key_size = bpf_map__key_size(map);
        value_size = bpf_map__value_size(map);
        max_entries = bpf_map__max_entries(map);
#else
        {
            const struct bpf_map_def *def = bpf_map__def(map);

            type = def->type;
            key_size = def->key_size;
            value_size = def->value_size;
            max_entries = def->max_entries;
        }
#endif
        fprintf(stdlog,
                "        \"%s\" : {\n"
                "            \"Info\" : { \"Length\" : { \"Key\" : %u, \"Value\" : %u},\n"
                "                       \"Type\" : %u,\n"
                "                       \"FD\" : %d,\n"
                "                       \"Configured Ports\" : [",
                name, key_size, value_size, type, fd);

        for (i = 0; i < port_count; i++) {
            fprintf(stdlog, "%s%u", (i) ? ", " : "", ports[i]);
        }

        fprintf(stdlog,
                "],\n"
                "                       \"Data\" : [\n"
                "                                    { \"Iteration\" : 1, \"Total\" : %u, \"Filled\" : %zu, \"Zero\" : %u }\n"
                "                                ]\n"
                "                      }\n"
                "        }",
                max_entries, port_count, max_entries - (uint32_t)port_count);
        return;
    }
}

static void dns_write_rcodes_json(FILE *stdlog, netdata_dns_rcode_counter_t *rcode)
{
    int first = 1;

    fprintf(stdlog, "{ ");
    while (rcode) {
        fprintf(stdlog, "%s\"%u\" : %u", first ? "" : ", ", rcode->code, rcode->count);
        first = 0;
        rcode = rcode->next;
    }
    fprintf(stdlog, " }");
}

static void dns_write_results_json(FILE *stdlog, const netdata_dns_collector_t *collector, int capture_seconds)
{
    netdata_dns_stats_t *stats = collector->stats;
    int first = 1;

    fprintf(stdlog,
            "        \"dns_results\" : {\n"
            "            \"Info\" : { \"Collection Seconds\" : %d,\n"
            "                       \"Timeout Window Usec\" : %llu,\n"
            "                       \"Pending Queries\" : %zu,\n"
            "                       \"Total Results\" : %zu,\n"
            "                       \"Data\" : [\n",
            capture_seconds, (unsigned long long)NETDATA_DNS_TIMEOUT_USEC,
            collector->pending_queries, collector->total_results);

    while (stats) {
        char server_ip[INET6_ADDRSTRLEN];
        char client_ip[INET6_ADDRSTRLEN];

        dns_format_ip(server_ip, sizeof(server_ip), stats->key.family, stats->key.server_ip);
        dns_format_ip(client_ip, sizeof(client_ip), stats->key.family, stats->key.client_ip);

        fprintf(stdlog,
                "%s"
                "                                    { \"server_ip\" : \"%s\", \"client_ip\" : \"%s\", "
                "\"client_port\" : %u, \"protocol\" : %u, \"query_type\" : %u, \"domain\" : \"%s\", "
                "\"stats\" : { \"Timeouts\" : %u, \"SuccessLatencySum\" : %llu, "
                "\"FailureLatencySum\" : %llu, \"CountByRcode\" : ",
                first ? "" : ",\n", server_ip, client_ip, stats->key.client_port,
                stats->key.protocol, stats->query_type, stats->domain, stats->timeouts,
                (unsigned long long)stats->success_latency_sum,
                (unsigned long long)stats->failure_latency_sum);
        dns_write_rcodes_json(stdlog, stats->rcodes);
        fprintf(stdlog, " } }");

        first = 0;
        stats = stats->next;
    }

    if (!first)
        fprintf(stdlog, "\n");

    fprintf(stdlog,
            "                                ]\n"
            "                      }\n"
            "        }");
}

static int dns_configure_ports(struct bpf_object *obj, const uint16_t *ports, size_t port_count, FILE *stdlog)
{
    struct bpf_map *map;
    const char *name = "dns_ports";

    bpf_object__for_each_map(map, obj) {
        const char *map_name = bpf_map__name(map);
        int fd;
        size_t i;
        uint8_t enabled = 1;

        if (strcmp(map_name, name))
            continue;

        fd = bpf_map__fd(map);
        for (i = 0; i < port_count; i++) {
            if (bpf_map_update_elem(fd, &ports[i], &enabled, BPF_ANY)) {
                fprintf(stdlog, "\"error\" : \"Cannot update dns port %u map entry.\",", ports[i]);
                return -1;
            }
        }

        return 0;
    }

    fprintf(stdlog, "\"error\" : \"Cannot find dns_ports map.\",");
    return -1;
}

static struct bpf_program *dns_find_socket_filter_program(struct bpf_object *obj)
{
    struct bpf_program *prog;

    bpf_object__for_each_program(prog, obj) {
        if (bpf_program__get_type(prog) == BPF_PROG_TYPE_SOCKET_FILTER)
            return prog;
    }

    return NULL;
}

static int dns_open_capture_socket(int program_fd)
{
    struct sockaddr_ll bind_addr = { };
    int sockfd;
    struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0)
        return -1;

    bind_addr.sll_family = AF_PACKET;
    bind_addr.sll_protocol = htons(ETH_P_ALL);
    if (bind(sockfd, (struct sockaddr *)&bind_addr, sizeof(bind_addr))) {
        close(sockfd);
        return -1;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_BPF, &program_fd, sizeof(program_fd))) {
        close(sockfd);
        return -1;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) {
        close(sockfd);
        return -1;
    }

    return sockfd;
}

static void dns_collect_packets(int sockfd, netdata_dns_collector_t *collector, int capture_seconds)
{
    uint8_t packet[NETDATA_DNS_PACKET_BUFFER];
    uint64_t end_usec = dns_now_usec() + ((uint64_t)capture_seconds * 1000000ULL);

    while (dns_now_usec() < end_usec) {
        ssize_t received = recv(sockfd, packet, sizeof(packet), 0);
        uint64_t now_usec = dns_now_usec();

        dns_expire_states(collector, now_usec);

        if (received <= 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;

            break;
        }

        {
            netdata_dns_packet_t dns_packet;

            if (!dns_parse_packet(packet, (size_t)received, &dns_packet))
                continue;

            if (!dns_packet.response)
                dns_process_query(collector, &dns_packet, now_usec);
            else
                dns_process_response(collector, &dns_packet, now_usec);
        }
    }

    dns_expire_states(collector, dns_now_usec());
}

int ebpf_object_has_socket_filter(struct bpf_object *obj)
{
    return dns_find_socket_filter_program(obj) != NULL;
}

const char *ebpf_socket_filter_tester(struct bpf_object *obj, uint32_t maps, FILE *stdlog, int iterations,
                                      const uint16_t *ports, size_t port_count)
{
    static const char *result[] = { "Success", "Fail" };
    struct bpf_program *prog;
    int sockfd;
    int capture_seconds = iterations * NETDATA_DNS_CAPTURE_INTERVAL;
    netdata_dns_collector_t collector = { };

    if (bpf_object__load(obj))
        return result[1];

    prog = dns_find_socket_filter_program(obj);
    if (!prog)
        return result[1];

    if (dns_configure_ports(obj, ports, port_count, stdlog))
        return result[1];

    sockfd = dns_open_capture_socket(bpf_program__fd(prog));
    if (sockfd < 0)
        return result[1];

    if (maps) {
        dns_collect_packets(sockfd, &collector, capture_seconds);
        dns_write_ports_json(stdlog, obj, ports, port_count);
        fprintf(stdlog, ",\n");
        dns_write_results_json(stdlog, &collector, capture_seconds);
        fprintf(stdlog, ",\n        \"Total tables\" : 2\n");
    }

    dns_free_collector(&collector);
    close(sockfd);

    return result[0];
}
