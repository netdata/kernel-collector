#ifndef NETDATA_LEGACY_TESTER_SOCKET
#define NETDATA_LEGACY_TESTER_SOCKET 1

#include <stdio.h>

struct bpf_object;

int  ebpf_object_has_socket_table(struct bpf_object *obj);
void ebpf_socket_table_tester(struct bpf_object *obj, FILE *out, int iterations);

#endif /* NETDATA_LEGACY_TESTER_SOCKET */
