#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include "netdata_tests.h"
#include "netdata_swap.h"

#include "swap.skel.h"

char *function_list[] = { "swap_readpage",
                          "swap_writepage" };

static void netdata_ebpf_disable_probe(struct swap_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_swap_readpage_probe, false);
    bpf_program__set_autoload(obj->progs.netdata_swap_writepage_probe, false);
}

static void netdata_ebpf_disable_trampoline(struct swap_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_swap_readpage_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_swap_writepage_fentry, false);
}

static void netdata_set_trampoline_target(struct swap_bpf *obj)
{
    bpf_program__set_attach_target(obj->progs.netdata_swap_readpage_fentry, 0,
                                   function_list[NETDATA_KEY_SWAP_READPAGE_CALL]);

    bpf_program__set_attach_target(obj->progs.netdata_swap_writepage_fentry, 0,
                                   function_list[NETDATA_KEY_SWAP_WRITEPAGE_CALL]);
}

static int attach_kprobe(struct swap_bpf *obj)
{
    obj->links.netdata_swap_readpage_probe = bpf_program__attach_kprobe(obj->progs.netdata_swap_readpage_probe,
                                                                        false, function_list[NETDATA_KEY_SWAP_READPAGE_CALL]);
    int ret = libbpf_get_error(obj->links.netdata_swap_readpage_probe);
    if (ret)
        return -1;

    obj->links.netdata_swap_writepage_probe = bpf_program__attach_kprobe(obj->progs.netdata_swap_writepage_probe,
                                                                         false, function_list[NETDATA_KEY_SWAP_WRITEPAGE_CALL]);
    ret = libbpf_get_error(obj->links.netdata_swap_writepage_probe);
    if (ret)
        return -1;

    return 0;
}

static int ebpf_load_and_attach(struct swap_bpf *obj, int selector)
{
    if (!selector) { //trampoline
        netdata_ebpf_disable_probe(obj);

        netdata_set_trampoline_target(obj);
    } else if (selector) { // probe
        netdata_ebpf_disable_trampoline(obj);
    }

    int ret = swap_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    }

    if (selector) // attach kprobe
        ret = attach_kprobe(obj);
    else {
        ret = swap_bpf__attach(obj);
    }

    if (!ret) {
        fprintf(stdout, "%s loaded with success\n", (!selector) ? "trampoline" : "probe");
    }

    return ret;
}

static pid_t ebpf_fill_tables(int global, int apps)
{
    pid_t pid = ebpf_fill_global(global);

    netdata_swap_access_t swap_data = { .read = 1, .write = 1 };

    uint32_t idx = (pid_t)pid;
    int ret = bpf_map_update_elem(apps, &idx, &swap_data, 0);
    if (ret)
        fprintf(stderr, "Cannot insert value to apps table.");

    return pid;
}

static int swap_read_apps_array(int fd, int ebpf_nprocs, uint32_t my_ip)
{
    netdata_swap_access_t *stored = calloc((size_t)ebpf_nprocs, sizeof(netdata_swap_access_t));
    if (!stored)
        return 2;

    uint64_t counter = 0;
    if (!bpf_map_lookup_elem(fd, &my_ip, stored)) {
        int j;
        for (j = 0; j < ebpf_nprocs; j++) {
            counter += (stored[j].read + stored[j].write);
        }
    }

    free(stored);

    if (counter) {
        fprintf(stdout, "Apps data stored with success\n");
        return 0;
    }

    return 2;
}

int ebpf_load_swap(int selector)
{
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);

    struct swap_bpf *obj = NULL;

    obj = swap_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");

        return 2;
    }

    int ret = ebpf_load_and_attach(obj, selector);
    if (!ret) {
        int fd = bpf_map__fd(obj->maps.swap_ctrl);
        update_controller_table(fd);

        fd = bpf_map__fd(obj->maps.tbl_swap);
        int fd2 = bpf_map__fd(obj->maps.tbl_pid_swap);
        pid_t my_pid = ebpf_fill_tables(fd, fd2);
        ret =  ebpf_read_global_array(fd, ebpf_nprocs, NETDATA_SWAP_END);
        if (!ret) {
            ret =  swap_read_apps_array(fd2, ebpf_nprocs, my_pid);
            if (ret)
                fprintf(stderr, "Cannot read apps table\n");
        } else
            fprintf(stderr, "Cannot read global table\n");
    } else 
        fprintf(stderr ,"%s", NETDATA_CORE_DEFAULT_ERROR);

    swap_bpf__destroy(obj);

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
                          ebpf_print_help(argv[0], "swap", 1);
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

    // Adjust memory
    int ret = netdata_ebf_memlock_limit();
    if (ret) {
        fprintf(stderr, "Cannot increase memory: error = %d\n", ret);
        return 1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    struct btf *bf = NULL;
    if (!selector) {
        bf = netdata_parse_btf_file((const char *)NETDATA_BTF_FILE);
        if (bf) {
            selector = ebpf_find_functions(bf, selector, function_list, NETDATA_SWAP_END);
            btf__free(bf);
        }
    }

    return ebpf_load_swap(selector);
}

