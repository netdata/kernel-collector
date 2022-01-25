#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include "netdata_tests.h"
#include "filesystem.skel.h"

#include "netdata_fs.h"

struct filesystem_data {
    const char *name;
    const char *path;
    const char *functions[NETDATA_FS_BTF_END];
    int ids[NETDATA_FS_BTF_END];
    struct btf *bf;
};

/* Files used with ext4 and btrfs, but the usage depends of
 * kerel compliation, to avoid problems we will use only probes.
#define NETDATA_EXT4_BTF_FILE "/sys/kernel/btf/ext4"
#define NETDATA_BTRFS_BTF_FILE "/sys/kernel/btf/btrfs"
*/

struct filesystem_data fd[] = {
    {   
        .name = "nfs",
        .path = NULL,
        .functions = {  "nfs_file_read",
                        "nfs_file_write",
                        "nfs_open",
                        "nfs_getattr",
                        NULL }, // "nfs4_file_open" - not present on all kernels
        .ids = { -1, -1, -1, -1, -1},
        .bf = NULL
    },
    {   
        .name = "ext4",
        .path = NULL,
        .functions = {  "ext4_file_read_iter",
                        "ext4_file_write_iter",
                        "ext4_file_open",
                        "ext4_sync_file",
                        NULL },
        .ids = { -1, -1, -1, -1, -1},
        .bf = NULL
    },
    {   
        .name = "btrfs",
        .path = NULL,
        .functions = {  "btrfs_file_read_iter",
                        "btrfs_file_write_iter",
                        "btrfs_file_open",
                        "btrfs_sync_file",
                        NULL },
        .ids = { -1, -1, -1, -1, -1},
        .bf = NULL
    },
    {   
        .name = "xfs",
        .path = NULL,
        .functions = {  "xfs_file_read_iter",
                        "xfs_file_write_iter",
                        "xfs_file_open",
                        "xfs_file_fsync",
                        NULL },
        .ids = { -1, -1, -1, -1, -1},
        .bf = NULL
    },
    {
        .name = NULL,
        .path = NULL,
        .functions = { NULL },
        .ids = { -1, -1, -1, -1, -1},
        .bf = NULL
    }
};

static int ebpf_load_btf_file(int idx)
{
    if (!fd[idx].path) {
        fprintf(stderr, "BTF file not given, use kprobe instead.\n");
        return -1;
    }

    fd[idx].bf = netdata_parse_btf_file(fd[idx].path);
    if (!fd[idx].bf) {
        fprintf(stderr, "Cannot load BTF file.\n");
        return -1;
    }

    return 0;
}

static int ebpf_find_ids(int idx)
{
    int *ids = fd[idx].ids;
    struct btf *bf = fd[idx].bf;
    int i;
    for (i = 0; i < NETDATA_FS_BTF_END ; i++) {
        if (fd[idx].functions[i]) {
            ids[i] = ebpf_find_function_id(bf, (char *)fd[idx].functions[i]);
            if (ids[i] < 0)
                return -1;
        }
    }

    return 0;
}

static void ebpf_clean_btf_file(int idx)
{
    if (fd[idx].bf)
        btf__free(fd[idx].bf);
}

static void ebpf_fs_disable_kprobe(struct filesystem_bpf *obj)
{
    // kprobe
    bpf_program__set_autoload(obj->progs.netdata_fs_file_read_probe, false);
    bpf_program__set_autoload(obj->progs.netdata_fs_file_write_probe, false);
    bpf_program__set_autoload(obj->progs.netdata_fs_file_open_probe, false);
    bpf_program__set_autoload(obj->progs.netdata_fs_2nd_file_open_probe, false);
    bpf_program__set_autoload(obj->progs.netdata_fs_getattr_probe, false);
    // kretprobe
    bpf_program__set_autoload(obj->progs.netdata_fs_file_read_retprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_fs_file_write_retprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_fs_file_open_retprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_fs_2nd_file_open_retprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_fs_getattr_retprobe, false);
}

static void ebpf_fs_set_target(struct filesystem_bpf *obj, const char **functions)
{
    // entry
    bpf_program__set_attach_target(obj->progs.netdata_fs_file_read_entry, 0,
                                   functions[NETDATA_KEY_BTF_READ]);
    bpf_program__set_attach_target(obj->progs.netdata_fs_file_write_entry, 0,
                                   functions[NETDATA_KEY_BTF_WRITE]);
    bpf_program__set_attach_target(obj->progs.netdata_fs_file_open_entry, 0,
                                   functions[NETDATA_KEY_BTF_OPEN]);
    bpf_program__set_attach_target(obj->progs.netdata_fs_getattr_entry, 0,
                                   functions[NETDATA_KEY_BTF_SYNC_ATTR]);

    // exit
    bpf_program__set_attach_target(obj->progs.netdata_fs_file_read_exit, 0,
                                   functions[NETDATA_KEY_BTF_READ]);
    bpf_program__set_attach_target(obj->progs.netdata_fs_file_write_exit, 0,
                                   functions[NETDATA_KEY_BTF_WRITE]);
    bpf_program__set_attach_target(obj->progs.netdata_fs_file_open_exit, 0,
                                   functions[NETDATA_KEY_BTF_OPEN]);
    bpf_program__set_attach_target(obj->progs.netdata_fs_getattr_exit, 0,
                                   functions[NETDATA_KEY_BTF_SYNC_ATTR]);

    if (functions[NETDATA_KEY_BTF_OPEN2]) {
        bpf_program__set_attach_target(obj->progs.netdata_fs_2nd_file_open_entry, 0,
                                       functions[NETDATA_KEY_BTF_OPEN2]);
        bpf_program__set_attach_target(obj->progs.netdata_fs_2nd_file_open_exit, 0,
                                       functions[NETDATA_KEY_BTF_OPEN2]);
    } else {
        bpf_program__set_autoload(obj->progs.netdata_fs_2nd_file_open_entry, false);
        bpf_program__set_autoload(obj->progs.netdata_fs_2nd_file_open_exit, false);
    }
}

static void ebpf_fs_disable_trampoline(struct filesystem_bpf *obj)
{
    // entry
    bpf_program__set_autoload(obj->progs.netdata_fs_file_read_entry, false);
    bpf_program__set_autoload(obj->progs.netdata_fs_file_write_entry, false);
    bpf_program__set_autoload(obj->progs.netdata_fs_file_open_entry, false);
    bpf_program__set_autoload(obj->progs.netdata_fs_getattr_entry, false);
    bpf_program__set_autoload(obj->progs.netdata_fs_2nd_file_open_entry, false);

    // exit
    bpf_program__set_autoload(obj->progs.netdata_fs_file_read_exit, false);
    bpf_program__set_autoload(obj->progs.netdata_fs_file_write_exit, false);
    bpf_program__set_autoload(obj->progs.netdata_fs_file_open_exit, false);
    bpf_program__set_autoload(obj->progs.netdata_fs_getattr_exit, false);
    bpf_program__set_autoload(obj->progs.netdata_fs_2nd_file_open_exit, false);
}

static int ebpf_fs_attach_kprobe(struct filesystem_bpf *obj, const char **functions)
{
    // kprobe
    obj->links.netdata_fs_file_read_probe = bpf_program__attach_kprobe(obj->progs.netdata_fs_file_read_probe,
                                                                false, functions[NETDATA_KEY_BTF_READ]);
    if (libbpf_get_error(obj->links.netdata_fs_file_read_probe))
        return -1;

    obj->links.netdata_fs_file_write_probe = bpf_program__attach_kprobe(obj->progs.netdata_fs_file_write_probe,
                                                                false, functions[NETDATA_KEY_BTF_WRITE]);
    if (libbpf_get_error(obj->links.netdata_fs_file_write_probe))
        return -1;

    obj->links.netdata_fs_file_open_probe = bpf_program__attach_kprobe(obj->progs.netdata_fs_file_open_probe,
                                                                false, functions[NETDATA_KEY_BTF_OPEN]);
    if (libbpf_get_error(obj->links.netdata_fs_file_open_probe))
        return -1;

    obj->links.netdata_fs_getattr_probe = bpf_program__attach_kprobe(obj->progs.netdata_fs_getattr_probe,
                                                                false, functions[NETDATA_KEY_BTF_SYNC_ATTR]);
    if (libbpf_get_error(obj->links.netdata_fs_getattr_probe))
        return -1;
    
    // kretprobe
    obj->links.netdata_fs_file_read_retprobe = bpf_program__attach_kprobe(obj->progs.netdata_fs_file_read_retprobe,
                                                                false, functions[NETDATA_KEY_BTF_READ]);
    if (libbpf_get_error(obj->links.netdata_fs_file_read_retprobe))
        return -1;

    obj->links.netdata_fs_file_write_retprobe = bpf_program__attach_kprobe(obj->progs.netdata_fs_file_write_retprobe,
                                                                false, functions[NETDATA_KEY_BTF_WRITE]);
    if (libbpf_get_error(obj->links.netdata_fs_file_write_retprobe))
        return -1;

    obj->links.netdata_fs_file_open_retprobe = bpf_program__attach_kprobe(obj->progs.netdata_fs_file_open_retprobe,
                                                                false, functions[NETDATA_KEY_BTF_OPEN]);
    if (libbpf_get_error(obj->links.netdata_fs_file_open_retprobe))
        return -1;

    obj->links.netdata_fs_getattr_retprobe = bpf_program__attach_kprobe(obj->progs.netdata_fs_getattr_retprobe,
                                                                false, functions[NETDATA_KEY_BTF_SYNC_ATTR]);
    if (libbpf_get_error(obj->links.netdata_fs_getattr_retprobe))
        return -1;

    if (functions[NETDATA_KEY_BTF_OPEN2]) {
        obj->links.netdata_fs_2nd_file_open_probe = bpf_program__attach_kprobe(obj->progs.netdata_fs_2nd_file_open_probe,
                                                                false, functions[NETDATA_KEY_BTF_OPEN2]);
        if (libbpf_get_error(obj->links.netdata_fs_2nd_file_open_probe))
            return -1;

        obj->links.netdata_fs_2nd_file_open_retprobe = bpf_program__attach_kprobe(obj->progs.netdata_fs_2nd_file_open_retprobe,
                                                                false, functions[NETDATA_KEY_BTF_OPEN2]);
        if (libbpf_get_error(obj->links.netdata_fs_2nd_file_open_retprobe))
            return -1;
    }

    return 0;
}

static inline int ebpf_load_and_attach(struct filesystem_bpf *obj, const char **functions,
                                       const char *name, struct btf *bf)
{
    if (bf) {
        ebpf_fs_disable_kprobe(obj);
        ebpf_fs_set_target(obj, functions);
    } else {
        ebpf_fs_disable_trampoline(obj);
    }

    int ret = filesystem_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    }

    if (bf)
        ret = filesystem_bpf__attach(obj);
    else
        ret = ebpf_fs_attach_kprobe(obj, functions);

    if (!ret)
        fprintf(stdout, "%s: %s loaded with success\n", name, (bf) ? "entry" : "probe");

     return ret;
}


static int ebpf_load_fs(int idx)
{
    struct filesystem_bpf *obj = NULL;
    obj = filesystem_bpf__open();
    if (obj) {
        ebpf_load_and_attach(obj, fd[idx].functions, fd[idx].name, fd[idx].bf);
        filesystem_bpf__destroy(obj);
    }

    return 0;
}

static inline void ebpf_print_fs_help(char *name, char *info) {
    fprintf(stdout, "%s tests if it is possible to monitor %s on host\n\n"
                    "The following options are available:\n\n"
                    "--help       (-h): Prints this help.\n"
                    "--nfs        (-n): Run tests for nfs filesystem\n" 
                    "--ext4       (-e): Run tests for ext4 filesystem\n" 
                    "--btrfs      (-b): Run tests for btrfs filesystem\n" 
                    "--xfs        (-x): Run tests for xfs filesystem\n" 
                    "\n\n"
                    "Usage: %s --ext4\n"
                    , name, info, name);
}

int main(int argc, char **argv)
{
    static struct option long_options[] = {
        {"help",        no_argument,    0,  'h' },
        {"nfs",         no_argument,    0,  'n' },
        {"ext4",        no_argument,    0,  'e' },
        {"btrfs",       no_argument,    0,  'b' },
        {"xfs",         no_argument,    0,  'x' },
        {0, 0, 0, 0}
    };

    // Selector is kept for the moment that distributions start compiling
    // their filesystem with support for trampoline, for while we are using
    // only probes
    int selector = 1;
    int option_index = 0;
    int fs = -1;
    while (1) {
        int c = getopt_long(argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h': {
                          ebpf_print_fs_help(argv[0], "filesystem");
                          exit(0);
                      }
            case 'n': {
                          fs = 0;
                          break;
                      }
            case 'e': {
                          fs = 1;
                          break;
                      }
            case 'b': {
                          fs = 2;
                          break;
                      }
            case 'x': {
                          fs = 3;
                          break;
                      }
            default: {
                         break;
                     }
        }
    }

    if (fs == -1) {
        ebpf_print_fs_help(argv[0], "filesystem");
        exit(1);
    }

    // Adjust memory
    int ret = netdata_ebf_memlock_limit();
    if (ret) {
        fprintf(stderr, "Cannot increase memory: error = %d\n", ret);
        return 2;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (!selector) {
        ret = ebpf_load_btf_file(fs);
        if (!ret) {
            ret = ebpf_find_ids(fs);
        }
    }

    // run tests here
    if (!ret) {
        ret = ebpf_load_fs(fs);
    }
    ebpf_clean_btf_file(fs);

    return ret;
}

