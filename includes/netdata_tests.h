// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_TESTS_H_
#define _NETDATA_TESTS_H_ 1

#define NETDATA_BTF_FILE "/sys/kernel/btf/vmlinux"

#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <sys/resource.h>
#include <linux/version.h>

#include <linux/btf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>

#define NETDATA_CORE_DEFAULT_ERROR "It was not possible to attach JIT code for your kernel, try another\n" \
                                    "method or use eBPF programs from ../kernel directory.\n "
#define NETDATA_KALLSYMS "/proc/kallsyms"

// Use __always_inline instead inline to keep compatiblity with old kernels

static inline int netdata_ebf_memlock_limit(void)
{
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        return -1;
    }

    return 0;
}

static inline struct btf *netdata_parse_btf_file(const char *filename)
{
    struct btf *bf = btf__parse(filename, NULL);
    if (libbpf_get_error(bf)) {
        fprintf(stderr, "Cannot parse btf file");
        btf__free(bf);
    }

    return bf;
}

static inline const struct btf_type *netdata_find_bpf_attach_type(struct btf *bf)
{
    int id = btf__find_by_name_kind(bf, "bpf_attach_type", BTF_KIND_ENUM);
    if (id < 0) {
        fprintf(stderr, "Cannot find 'bpf_attach_type'");

        return NULL;
    }

    return btf__type_by_id(bf, id);
}

enum netdata_modes {
    NETDATA_MODE_TRAMPOLINE,
    NETDATA_MODE_PROBE,
    NETDATA_MODE_TRACEPOINT
};

static inline void ebpf_print_help(char *name, char *info, int has_trampoline) {
    fprintf(stdout, "%s tests if it is possible to monitor %s on host\n\n"
                    "The following options are available:\n\n"
                    "--help       (-h): Prints this help.\n"
                    "--probe      (-p): Use probe and do no try to use trampolines (fentry/fexit).\n"
                    "--tracepoint (-r): Use tracepoint.\n"
                    , name, info);
    if (has_trampoline)
        fprintf(stdout, "--trampoline (-t): Try to use trampoline(fentry/fexit). If this is not possible" 
                        " probes will be used.\n");
}

static inline void ebpf_tracepoint_help(char *name) {
    fprintf(stdout, "%s tests if it is possible to use tracepoints on host\n\n"
                    "--help       (-h): Prints this help.\n", name);
}


static inline int ebpf_find_function_id(struct btf *bf, char *name)
{
    const struct btf_type *type = netdata_find_bpf_attach_type(bf);
    if (!type)
        return -1;

    const struct btf_enum *e = btf_enum(type);
    int i, id;
    for (id = -1, i = 0; i < btf_vlen(type); i++, e++) {
        if (!strcmp(btf__name_by_offset(bf, e->name_off), "BPF_TRACE_FENTRY")) {
            id = btf__find_by_name_kind(bf, name, BTF_KIND_FUNC);
            break;
        }
    }

    return id;
}

static inline char *ebpf_select_type(int selector)
{
    switch(selector)
    {
        case 0: {
                    return "trampoline";
                }
        case 1: {
                    return "probe";
                }
        case 2: {
                    return "tracepoint";
                }
    }

    return NULL;
}

static inline void update_controller_table(int fd)
{
    uint32_t key = NETDATA_CONTROLLER_APPS_ENABLED;
    uint32_t value = 1;
    int ret = bpf_map_update_elem(fd, &key, &value, 0);
    if (ret)
        fprintf(stderr, "Cannot insert value to control table.");
}

static inline int ebpf_find_functions(struct btf *bf, int selector, char *syscalls[], uint32_t end)
{
    if (!bf)
        return selector;

    uint32_t i;
    for (i = 0; i < end; i++) {
        if (ebpf_find_function_id(bf, syscalls[i]) < 0 ) {
            fprintf(stderr, "Cannot find function %s\n", syscalls[i]);
            selector = NETDATA_MODE_PROBE;
            break;
        }
    }

    return selector;
}

static inline int ebpf_read_global_array(int fd, int ebpf_nprocs, uint32_t end)
{
    uint64_t *stored = calloc((size_t)ebpf_nprocs, sizeof(uint64_t));
    if (!stored)
        return 2;

    size_t length = (size_t)ebpf_nprocs * sizeof(uint64_t);
    uint32_t idx;
    uint64_t counter = 0;
    for (idx = 0; idx < end; idx++) {
        if (!bpf_map_lookup_elem(fd, &idx, stored)) {
            int j;
            for (j = 0; j < ebpf_nprocs; j++) {
                counter += stored[j];
            }
        }

        memset(stored, 0, length);
    }

    free(stored);

    // Some testers store only one value, so for every value different of zero
    // the result will be successful
    if (counter) {
        fprintf(stdout, "Global data stored with success\n");
        return 0;
    }

    return 2;
}

static inline pid_t ebpf_fill_global(int fd)
{
    pid_t pid = getpid();
    uint32_t idx = 0;
    uint64_t value = 1;

    int ret = bpf_map_update_elem(fd, &idx, &value, 0);
    if (ret)
        fprintf(stderr, "Cannot insert value to global table.");

    return pid;
}

static inline char *netdata_update_name(char *search)
{
    char filename[FILENAME_MAX + 1];
    char data[128];
    char *ret = NULL;
    snprintf(filename, FILENAME_MAX, "%s", NETDATA_KALLSYMS);
    FILE *fp = fopen(filename, "r");
    if (!fp)
        return NULL;

    char *parse;
    size_t length = strlen(search);
    while ( (parse = fgets(data, 127, fp)) ) {
        parse += 19;
        if (!strncmp(search, parse, length) ) {
            char *end;
            for (end = parse; isalnum(*end) || *end == '_' || *end == '.'; end++);
            if (end) {
                *end = '\0';
                ret = strdup(parse);
            }

            break;
        } 
    }

    fclose(fp);

    return ret;
}

#endif /* _NETDATA_TESTS_H_ */

