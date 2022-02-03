#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#include <linux/version.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include <sys/stat.h>

#include "netdata_tests.h"
#include "netdata_cache.h"

#include "cachestat.skel.h"

char *syscalls[] = { "add_to_page_cache_lru",
                     "mark_page_accessed",
#if (MY_LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0))
                     "__folio_mark_dirty",
#elif (MY_LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0))
                     "__set_page_dirty",
#else
                     "account_page_dirtied",
#endif
                     "mark_buffer_dirty"
};

static inline void netdata_ebpf_disable_probe(struct cachestat_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_add_to_page_cache_lru_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_mark_page_accessed_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_folio_mark_dirty_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_set_page_dirty_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_account_page_dirtied_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_mark_buffer_dirty_kprobe, false);
}

static inline void netdata_ebpf_disable_specific_probe(struct cachestat_bpf *obj)
{
#if (MY_LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0))
    bpf_program__set_autoload(obj->progs.netdata_account_page_dirtied_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_set_page_dirty_kprobe, false);
#elif (MY_LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0))
    bpf_program__set_autoload(obj->progs.netdata_folio_mark_dirty_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_account_page_dirtied_kprobe, false);
#else
    bpf_program__set_autoload(obj->progs.netdata_folio_mark_dirty_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_set_page_dirty_kprobe, false);
#endif
}

static inline void netdata_ebpf_disable_trampoline(struct cachestat_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_add_to_page_cache_lru_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_mark_page_accessed_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_folio_mark_dirty_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_set_page_dirty_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_account_page_dirtied_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_mark_buffer_dirty_fentry, false);
}

static inline void netdata_ebpf_disable_specific_trampoline(struct cachestat_bpf *obj)
{
#if (MY_LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0))
    bpf_program__set_autoload(obj->progs.netdata_account_page_dirtied_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_set_page_dirty_fentry, false);
#elif (MY_LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0))
    bpf_program__set_autoload(obj->progs.netdata_folio_mark_dirty_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_account_page_dirtied_fentry, false);
#else
    bpf_program__set_autoload(obj->progs.netdata_folio_mark_dirty_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_set_page_dirty_fentry, false);
#endif
}

static inline void netdata_set_trampoline_target(struct cachestat_bpf *obj)
{
    bpf_program__set_attach_target(obj->progs.netdata_add_to_page_cache_lru_fentry, 0,
                                   syscalls[NETDATA_KEY_CALLS_ADD_TO_PAGE_CACHE_LRU]);

    bpf_program__set_attach_target(obj->progs.netdata_mark_page_accessed_fentry, 0,
                                   syscalls[NETDATA_KEY_CALLS_MARK_PAGE_ACCESSED]);

#if (MY_LINUX_VERSION_CODE > KERNEL_VERSION(5,16,0))
    bpf_program__set_attach_target(obj->progs.netdata_folio_mark_dirty_fentry, 0,
                                   syscalls[NETDATA_KEY_CALLS_ACCOUNT_PAGE_DIRTIED]);
#elif (MY_LINUX_VERSION_CODE > KERNEL_VERSION(5,15,0))
    bpf_program__set_attach_target(obj->progs.netdata_set_page_dirty_fentry, 0,
                                   syscalls[NETDATA_KEY_CALLS_ACCOUNT_PAGE_DIRTIED]);
#else
    bpf_program__set_attach_target(obj->progs.netdata_account_page_dirtied_fentry, 0,
                                   syscalls[NETDATA_KEY_CALLS_ACCOUNT_PAGE_DIRTIED]);
#endif

    bpf_program__set_attach_target(obj->progs.netdata_mark_buffer_dirty_fentry, 0,
                                   syscalls[NETDATA_KEY_CALLS_MARK_BUFFER_DIRTY]);
}

static inline int ebpf_load_and_attach(struct cachestat_bpf *obj, int selector)
{
    if (!selector) { //trampoline
        netdata_ebpf_disable_probe(obj);
        netdata_ebpf_disable_specific_trampoline(obj);

        netdata_set_trampoline_target(obj);
    } else { // probe
        netdata_ebpf_disable_trampoline(obj);
        netdata_ebpf_disable_specific_probe(obj);
    } 

    int ret = cachestat_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    }

    ret = cachestat_bpf__attach(obj);

    if (!ret) {
        fprintf(stdout, "%s: loaded with success\n", (!selector) ? "trampoline" : "probe");
    }

    return ret;
}

static pid_t ebpf_update_tables(int global, int apps)
{
    pid_t pid = getpid();
    uint32_t idx = 0;
    uint64_t value = 1;

    int ret = bpf_map_update_elem(global, &idx, &value, 0);
    if (ret)
        fprintf(stderr, "Cannot insert value to global table.");

    netdata_cachestat_t stats = { .add_to_page_cache_lru = 1, .mark_page_accessed = 1,
                                        .account_page_dirtied = 1, .mark_buffer_dirty = 1 };

    idx = (pid_t)pid;
    ret = bpf_map_update_elem(apps, &idx, &stats, 0);
    if (ret)
        fprintf(stderr, "Cannot insert value to apps table.");

    return pid;
}

static int cachestat_read_apps_array(int fd, int ebpf_nprocs, uint32_t child)
{
    netdata_cachestat_t *stored = calloc((size_t)ebpf_nprocs, sizeof(netdata_cachestat_t));
    if (!stored)
        return 2;

    uint32_t my_pid = (uint32_t) getpid();

    uint64_t counter = 0;
    if (!bpf_map_lookup_elem(fd, &my_pid, stored)) {
        int j;
        for (j = 0; j < ebpf_nprocs; j++) {
            counter += (stored[j].add_to_page_cache_lru + stored[j].mark_page_accessed +
                        stored[j].account_page_dirtied + stored[j].mark_buffer_dirty);
        }
    }

    free(stored);

    if (counter) {
        fprintf(stdout, "Apps data stored with success\n");
        return 0;
    }

    return 2;
}


static int ebpf_cachestat_tests(int selector)
{
    struct cachestat_bpf *obj = NULL;
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);

    obj = cachestat_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");

        return 2;
    }

    int ret = ebpf_load_and_attach(obj, selector);
    if (!ret) {
        int fd = bpf_map__fd(obj->maps.cstat_ctrl);
        update_controller_table(fd);

        fd = bpf_map__fd(obj->maps.cstat_global);
        int fd2 = bpf_map__fd(obj->maps.cstat_pid);
        pid_t my_pid = ebpf_update_tables(fd, fd2);
        ret =  ebpf_read_global_array(fd, ebpf_nprocs, NETDATA_CACHESTAT_END);
        if (!ret) {
            ret = cachestat_read_apps_array(fd2, ebpf_nprocs, (uint32_t)my_pid);
            if (ret)
                fprintf(stderr, "Cannot read apps table\n");
        } else
            fprintf(stderr, "Cannot read global table\n");
    } else
        fprintf(stderr ,"%s", NETDATA_CORE_DEFAULT_ERROR);

    cachestat_bpf__destroy(obj);

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
                          ebpf_print_help(argv[0], "cachestat", 1);
                          exit(0);
                      }
            case 'p': {
                          selector = NETDATA_MODE_PROBE;
                          break;
                      }
            case 'r': {
                          fprintf(stdout, "This specific software does not have tracepoint, using kprobe instead\n");
                          selector = NETDATA_MODE_PROBE;
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
        if (bf)
            selector = ebpf_find_functions(bf, selector, syscalls, NETDATA_CACHESTAT_END);
    }

    return ebpf_cachestat_tests(selector);
}

