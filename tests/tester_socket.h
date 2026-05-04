#ifndef NETDATA_LEGACY_TESTER_SOCKET
#define NETDATA_LEGACY_TESTER_SOCKET 1

#include <stdio.h>

struct bpf_object;
struct bpf_map;

struct bpf_map *ebpf_find_socket_table(struct bpf_object *obj);
struct bpf_map *ebpf_find_socket_events(struct bpf_object *obj);
void            ebpf_socket_table_tester(struct bpf_map *map, FILE *out, int iterations);
void            ebpf_socket_ringbuf_tester(struct bpf_map *map, FILE *out, int iterations);

#endif /* NETDATA_LEGACY_TESTER_SOCKET */
