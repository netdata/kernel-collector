#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/mount.h>

#include "netdata_tests.h"
#include "netdata_mount.h"

#include "mount.skel.h"

enum netdata_mount_syscalls {
    NETDATA_MOUNT_SYSCALL,
    NETDATA_UMOUNT_SYSCALL,

    NETDATA_MOUNT_SYSCALLS_END
};

char *syscalls[] = { "__x64_sys_mount",
                     "__x64_sys_umount" };

static int attach_probe(struct mount_bpf *obj)
{
    obj->links.netdata_mount_probe = bpf_program__attach_kprobe(obj->progs.netdata_mount_probe,
                                                                false, syscalls[NETDATA_MOUNT_SYSCALL]);
    int ret = libbpf_get_error(obj->links.netdata_mount_probe);
    if (ret)
        return -1;

    obj->links.netdata_mount_retprobe = bpf_program__attach_kprobe(obj->progs.netdata_mount_retprobe,
                                                                   true, syscalls[NETDATA_MOUNT_SYSCALL]);
    ret = libbpf_get_error(obj->links.netdata_mount_retprobe);
    if (ret)
        return -1;

    obj->links.netdata_umount_probe = bpf_program__attach_kprobe(obj->progs.netdata_umount_probe,
                                                                 false, syscalls[NETDATA_UMOUNT_SYSCALL]);
    ret = libbpf_get_error(obj->links.netdata_umount_probe);
    if (ret)
        return -1;

    obj->links.netdata_umount_retprobe = bpf_program__attach_kprobe(obj->progs.netdata_umount_retprobe,
                                                                    true, syscalls[NETDATA_UMOUNT_SYSCALL]);
    ret = libbpf_get_error(obj->links.netdata_umount_retprobe);
    if (ret)
        return -1;

    return 0;
}

static inline void netdata_ebpf_disable_probe(struct mount_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_mount_probe, false);
    bpf_program__set_autoload(obj->progs.netdata_mount_retprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_umount_probe, false);
    bpf_program__set_autoload(obj->progs.netdata_umount_retprobe, false);
}

static inline void netdata_ebpf_disable_tracepoint(struct mount_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_mount_exit, false);
    bpf_program__set_autoload(obj->progs.netdata_umount_exit, false);
}

static inline void netdata_ebpf_disable_trampoline(struct mount_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_mount_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_umount_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_mount_fexit, false);
    bpf_program__set_autoload(obj->progs.netdata_umount_fexit, false);
}

static inline void netdata_set_trampoline_target(struct mount_bpf *obj)
{
    bpf_program__set_attach_target(obj->progs.netdata_mount_fentry, 0,
                                   syscalls[NETDATA_MOUNT_SYSCALL]);

    bpf_program__set_attach_target(obj->progs.netdata_mount_fexit, 0,
                                   syscalls[NETDATA_MOUNT_SYSCALL]);

    bpf_program__set_attach_target(obj->progs.netdata_umount_fentry, 0,
                                   syscalls[NETDATA_UMOUNT_SYSCALL]);

    bpf_program__set_attach_target(obj->progs.netdata_umount_fexit, 0,
                                   syscalls[NETDATA_UMOUNT_SYSCALL]);
}

static inline int ebpf_load_and_attach(struct mount_bpf *obj, int selector)
{
    if (!selector) { //trampoline
        netdata_ebpf_disable_probe(obj);
        netdata_ebpf_disable_tracepoint(obj);

        netdata_set_trampoline_target(obj);
    } else if (selector == 1) { // probe
        netdata_ebpf_disable_trampoline(obj);
        netdata_ebpf_disable_tracepoint(obj);
    } else { // tracepoint
        netdata_ebpf_disable_probe(obj);
        netdata_ebpf_disable_trampoline(obj);
    }

    int ret = mount_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    }

    if (selector == 1) // attach kprobe
        ret = attach_probe(obj);
    else {
        ret = mount_bpf__attach(obj);
    }

    if (!ret) {
        fprintf(stdout, "%s loaded with success\n", (selector) ? "tracepoint" : "probe");
    }

    return ret;
}

static int call_syscalls()
{
    char *dst = { "./mydst" };
    if (mkdir(dst, 0777)) {
        fprintf(stdout, "Cannot create directory\n");
        return -1;
    }

    // I am not testing return, because errors are also stored at hash map
    (void)mount("none", dst, "tmpfs", 0, "mode=0777");
    (void)umount(dst);

    rmdir(dst);

    return 0;
}

static int mount_read_array(int fd)
{
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);
    uint64_t *stored = calloc((size_t)ebpf_nprocs, sizeof(uint64_t));
    if (!stored)
        return 2;

    uint32_t idx;
    uint64_t counter = 0;
    for (idx = 0; idx < NETDATA_MOUNT_END; idx++)  {
        if (!bpf_map_lookup_elem(fd, &idx, stored)) {
            int j;
            for (j = 0; j < ebpf_nprocs; j++) {
                counter += stored[j];
            }
        }

        memset(stored, 0, sizeof(uint64_t) * ebpf_nprocs);
    }

    free(stored);

    if (counter >= 2) {
        fprintf(stdout, "Data stored with success\n");
        return 0;
    }

    return 2;
}

static int ebpf_mount_tests(int selector)
{
    struct mount_bpf *obj = NULL;

    obj = mount_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");

        return 2;
    }

    int ret = ebpf_load_and_attach(obj, selector);
    if (!ret) {
        ret = call_syscalls();
        if (!ret) {
            int fd = bpf_map__fd(obj->maps.tbl_mount);
            ret = mount_read_array(fd);
        }
    } else
        fprintf(stderr ,"%s", NETDATA_CORE_DEFAULT_ERROR);

    mount_bpf__destroy(obj);

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

    int selector = 0;
    int option_index = 0;
    while (1) {
        int c = getopt_long(argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h': {
                          ebpf_print_help(argv[0], "mount", 1);
                          exit(0);
                      }
            case 'p': {
                          selector = 1;
                          break;
                      }
            case 'r': {
                          selector = 2;
                          break;
                      }
            case 't': {
                          selector = 0;
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
            selector = ebpf_find_functions(bf, selector, syscalls, NETDATA_MOUNT_SYSCALLS_END);
    }

    return ebpf_mount_tests(selector);
}

