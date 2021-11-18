// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_TESTS_H_
#define _NETDATA_TESTS_H_ 1

#define NETDATA_BTF_FILE "/sys/kernel/btf/vmlinux"

#include <sys/resource.h>
#include <linux/version.h>

#include <linux/btf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>

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

#endif /* _NETDATA_TESTS_H_ */

