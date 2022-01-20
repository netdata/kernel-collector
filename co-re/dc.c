#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include "netdata_tests.h"
#include "netdata_dc.h"

#include "dc.skel.h"

char *function_list[] = { "lookup_fast",
                          "d_lookup" };

static inline void ebpf_disable_probes(struct dc_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_lookup_fast_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_d_lookup_kretprobe, false);
}

static inline void ebpf_disable_trampoline(struct dc_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_lookup_fast_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_d_lookup_fexit, false);
}

static void ebpf_set_trampoline_target(struct dc_bpf *obj)
{
    bpf_program__set_attach_target(obj->progs.netdata_lookup_fast_fentry, 0,
                                   function_list[NETDATA_LOOKUP_FAST]);

    bpf_program__set_attach_target(obj->progs.netdata_d_lookup_fexit, 0,
                                   function_list[NETDATA_D_LOOKUP]);
}

static int ebpf_attach_probes(struct dc_bpf *obj)
{
    obj->links.netdata_d_lookup_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_d_lookup_kretprobe,
                                                                       true, function_list[NETDATA_D_LOOKUP]);
    int ret = libbpf_get_error(obj->links.netdata_d_lookup_kretprobe);
    if (ret)
        return -1;

    obj->links.netdata_lookup_fast_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_lookup_fast_kprobe,
                                                                       false, function_list[NETDATA_LOOKUP_FAST]);
    ret = libbpf_get_error(obj->links.netdata_lookup_fast_kprobe);
    if (ret)
        return -1;

    return 0;
}

static inline int ebpf_load_and_attach(struct dc_bpf *obj, int selector)
{
    // Adjust memory
    int ret;
    if (!selector) { // trampoline
        ebpf_disable_probes(obj);

        ebpf_set_trampoline_target(obj);
    } else if (selector == NETDATA_MODE_PROBE) {  // kprobe
        ebpf_disable_trampoline(obj);
    }

    ret = dc_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    } 

    if (!selector) {
        ret = dc_bpf__attach(obj);
    } else {
        ret = ebpf_attach_probes(obj);
    }
    
    if (!ret) {
        fprintf(stdout, "Directory Cache loaded with success\n");
    }

    return ret;
}

static int dc_read_apps_array(int fd, int ebpf_nprocs, uint32_t my_pid)
{
    netdata_dc_stat_t *stored = calloc((size_t)ebpf_nprocs, sizeof(netdata_dc_stat_t));
    if (!stored)
        return 2;

    uint64_t counter = 0;
    if (!bpf_map_lookup_elem(fd, &my_pid, stored)) {
        int j;
        for (j = 0; j < ebpf_nprocs; j++) {
            counter += (stored[j].references + stored[j].slow +
                        stored[j].missed);
        }
    }

    free(stored);

    if (counter) {
        fprintf(stdout, "Apps data stored with success\n");
        return 0;
    }

    return 2;
}

static pid_t ebpf_update_tables(int global, int apps)
{
    pid_t pid = ebpf_fill_global(global);

    netdata_dc_stat_t stats = { .references = 1, .slow = 1, .missed = 1};

    uint32_t idx = (uint32_t)pid;
    int ret = bpf_map_update_elem(apps, &idx, &stats, 0);
    if (ret)
        fprintf(stderr, "Cannot insert value to apps table.");

    return pid;
}

static int ebpf_dc_tests(int selector)
{
    struct dc_bpf *obj = NULL;
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);

    obj = dc_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");

        return 2;
    }

    int ret = ebpf_load_and_attach(obj, selector);
    if (!ret) {
        int fd = bpf_map__fd(obj->maps.dcstat_ctrl);
        update_controller_table(fd);

        fd = bpf_map__fd(obj->maps.dcstat_global);
        int fd2 = bpf_map__fd(obj->maps.dcstat_pid);
        pid_t my_pid = ebpf_update_tables(fd, fd2);

        ret =  ebpf_read_global_array(fd, ebpf_nprocs, NETDATA_DIRECTORY_CACHE_END);
        if (!ret) {
            ret = dc_read_apps_array(fd2, ebpf_nprocs, (uint32_t)my_pid);
            if (ret)
                fprintf(stderr, "Cannot read apps table\n");
        } else
            fprintf(stderr, "Cannot read global table\n");
    } else
        fprintf(stderr ,"%s", NETDATA_CORE_DEFAULT_ERROR);

    dc_bpf__destroy(obj);

    return ret;
}

int main(int argc, char **argv)
{
    static struct option long_options[] = {
        {"help",        no_argument,    0,  'h' },
        {"probe",       no_argument,    0,  'p' },
        {"tracepoint",  no_argument,    0,  'r' },
        {"trampoline",  no_argument,    0,  't' },
        {0, 0, 0, 0}
    };

    int selector = NETDATA_MODE_TRAMPOLINE;
    int option_index = 0;
    while (1) {
        int c = getopt_long(argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h': {
                          ebpf_print_help(argv[0], "dc", 1);
                          exit(0);
                      }
            case 'p': {
                          selector = NETDATA_MODE_PROBE;
                          break;
                      }
            case 'r': {
                          selector = NETDATA_MODE_PROBE;
                          fprintf(stdout, "This specific software does not have tracepoint, using kprobe instead\n");
                          break;
                      }
            case 't': {
                          selector = NETDATA_MODE_TRAMPOLINE;
                          break;
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

    char *lookup_fast = netdata_update_name(function_list[NETDATA_LOOKUP_FAST]);
    if (!lookup_fast) {
        return -1;
    }
    function_list[NETDATA_LOOKUP_FAST] = lookup_fast;

    struct btf *bf = NULL;
    if (!selector) {
        bf = netdata_parse_btf_file((const char *)NETDATA_BTF_FILE);
        if (bf) {
            selector = ebpf_find_functions(bf, selector, function_list, NETDATA_DC_COUNTER);
            btf__free(bf);
        }
    }

    ret =  ebpf_dc_tests(selector);

    free(lookup_fast);

    return ret;
}

