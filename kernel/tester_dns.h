#ifndef NETDATA_LEGACY_TESTER_DNS
#define NETDATA_LEGACY_TESTER_DNS 1

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct bpf_object;

int ebpf_object_has_socket_filter(struct bpf_object *obj);
const char *ebpf_socket_filter_tester(struct bpf_object *obj, uint32_t maps, FILE *stdlog, int iterations,
                                      const uint16_t *ports, size_t port_count);

#endif /* NETDATA_LEGACY_TESTER_DNS */
