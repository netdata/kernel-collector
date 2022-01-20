#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include "netdata_tests.h"

#include "hardirq.skel.h"

// Copied and redefined from ../include/netdata_hardirq.h
#define NETDATA_HARDIRQ_NAME_LEN 32
typedef struct hardirq_val {
    // incremental counter storing the total latency so far.
    uint64_t latency;

    // temporary timestamp stored at the IRQ entry handler, to be diff'd with a
    // timestamp at the IRQ exit handler, to get the latency to add to the
    // `latency` field.
    uint64_t ts;

    // identifies the IRQ with a human-readable string.
    char name[NETDATA_HARDIRQ_NAME_LEN];
} hardirq_val_t;

static inline int ebpf_load_and_attach(struct hardirq_bpf *obj)
{
    int ret = hardirq_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    } 

    ret = hardirq_bpf__attach(obj);
    if (!ret) {
        fprintf(stdout, "Hardirq loaded with success\n");
    }

    return ret;
}

static void ebpf_update_table(int global)
{
    uint32_t idx = 0;
    hardirq_val_t value =  { .ts = 1, .latency = 1, .name = "netdata_testing" };
    int ret = bpf_map_update_elem(global, &idx, &value, 0);
    if (ret)
        fprintf(stderr, "Cannot insert value to global table.");
}

static int hardirq_read_array(int fd, int ebpf_nprocs)
{
    hardirq_val_t *stored = calloc((size_t)ebpf_nprocs, sizeof(hardirq_val_t));
    if (!stored)
        return 2;

    uint64_t counter = 0;
    int idx = 0;
    if (!bpf_map_lookup_elem(fd, &idx, stored)) {
        int j;
        for (j = 0; j < ebpf_nprocs; j++) {
            counter += stored[j].ts + stored[j].latency;
        }
    }

    free(stored);

    if (counter) {
        fprintf(stdout, "Data stored with success\n");
        return 0;
    }

    return 2;
}

static int ebpf_hardirq_tests()
{
    struct hardirq_bpf *obj = NULL;
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);

    obj = hardirq_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");

        return 2;
    }

    int ret = ebpf_load_and_attach(obj);
    if (!ret) {
        int fd = bpf_map__fd(obj->maps.tbl_hardirq);
        ebpf_update_table(fd);

        ret = hardirq_read_array(fd, ebpf_nprocs);
        if (ret)
            fprintf(stderr, "Cannot read global table\n");
    } else
        fprintf(stderr ,"%s", NETDATA_CORE_DEFAULT_ERROR);

    hardirq_bpf__destroy(obj);

    return ret;
}

int main(int argc, char **argv)
{
    static struct option long_options[] = {
        {"help",        no_argument,    0,  'h' },
        {0, 0, 0, 0}
    };

    int option_index = 0;
    while (1) {
        int c = getopt_long(argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h': {
                          ebpf_tracepoint_help("hardirq");
                          exit(0);
                      }
            default: {
                         break;
                     }
        }
    }

    int ret = netdata_ebf_memlock_limit();
    if (ret) {
        fprintf(stderr, "Cannot increase memory: error = %d\n", ret);
        return 1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    return ebpf_hardirq_tests();
}

