#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include "netdata_tests.h"
#include "netdata_vfs.h"

#include "vfs.skel.h"

char *function_list[] = { "vfs_write",
                          "vfs_writev",
                          "vfs_read", 
                          "vfs_readv",
                          "vfs_unlink",
                          "vfs_fsync",
                          "vfs_open",
                          "vfs_create"
};

static inline void ebpf_disable_probes(struct vfs_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_vfs_write_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_write_kretprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_writev_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_writev_kretprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_read_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_read_kretprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_readv_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_readv_kretprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_unlink_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_unlink_kretprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_fsync_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_fsync_kretprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_open_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_open_kretprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_create_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_create_kretprobe, false);
}

static inline void ebpf_disable_trampoline(struct vfs_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_vfs_write_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_write_fexit, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_writev_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_writev_fexit, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_read_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_read_fexit, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_readv_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_readv_fexit, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_unlink_fentry, false);
//    bpf_program__set_autoload(obj->progs.netdata_vfs_unlink_fexit, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_fsync_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_fsync_fexit, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_open_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_open_fexit, false);
    bpf_program__set_autoload(obj->progs.netdata_vfs_create_fentry, false);
//    bpf_program__set_autoload(obj->progs.netdata_vfs_create_fexit, false);
}

static void ebpf_set_trampoline_target(struct vfs_bpf *obj)
{
    bpf_program__set_attach_target(obj->progs.netdata_vfs_write_fentry, 0,
                                   function_list[NETDATA_VFS_WRITE]);

    bpf_program__set_attach_target(obj->progs.netdata_vfs_write_fexit, 0,
                                   function_list[NETDATA_VFS_WRITE]);

    bpf_program__set_attach_target(obj->progs.netdata_vfs_writev_fentry, 0,
                                   function_list[NETDATA_VFS_WRITEV]);

    bpf_program__set_attach_target(obj->progs.netdata_vfs_writev_fexit, 0,
                                   function_list[NETDATA_VFS_WRITEV]);

    bpf_program__set_attach_target(obj->progs.netdata_vfs_read_fentry, 0,
                                   function_list[NETDATA_VFS_READ]);

    bpf_program__set_attach_target(obj->progs.netdata_vfs_read_fexit, 0,
                                   function_list[NETDATA_VFS_READ]);

    bpf_program__set_attach_target(obj->progs.netdata_vfs_readv_fentry, 0,
                                   function_list[NETDATA_VFS_READV]);

    bpf_program__set_attach_target(obj->progs.netdata_vfs_readv_fexit, 0,
                                   function_list[NETDATA_VFS_READV]);

    bpf_program__set_attach_target(obj->progs.netdata_vfs_unlink_fentry, 0,
                                   function_list[NETDATA_VFS_UNLINK]);

//    bpf_program__set_attach_target(obj->progs.netdata_vfs_unlink_fexit, 0,
//                                   function_list[NETDATA_VFS_UNLINK]);

    bpf_program__set_attach_target(obj->progs.netdata_vfs_fsync_fentry, 0,
                                   function_list[NETDATA_VFS_FSYNC]);

    bpf_program__set_attach_target(obj->progs.netdata_vfs_fsync_fexit, 0,
                                   function_list[NETDATA_VFS_FSYNC]);

    bpf_program__set_attach_target(obj->progs.netdata_vfs_open_fentry, 0,
                                   function_list[NETDATA_VFS_OPEN]);

    bpf_program__set_attach_target(obj->progs.netdata_vfs_open_fexit, 0,
                                   function_list[NETDATA_VFS_OPEN]);

    bpf_program__set_attach_target(obj->progs.netdata_vfs_create_fentry, 0,
                                   function_list[NETDATA_VFS_CREATE]);

//    bpf_program__set_attach_target(obj->progs.netdata_vfs_create_fexit, 0,
//                                   function_list[NETDATA_VFS_CREATE]);
}

#if (MY_LINUX_VERSION_CODE <= KERNEL_VERSION(5,6,0))
static void ebpf_disable_specific_trampoline(struct vfs_bpf *obj)
{
//    bpf_program__set_autoload(obj->progs.netdata_vfs_unlink_fexit, false);
//    bpf_program__set_autoload(obj->progs.netdata_vfs_create_fexit, false);
}
#endif

static int ebpf_attach_probes(struct vfs_bpf *obj)
{
    obj->links.netdata_vfs_write_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_vfs_write_kprobe,
                                                                     false, function_list[NETDATA_VFS_WRITE]);
    int ret = libbpf_get_error(obj->links.netdata_vfs_write_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_vfs_write_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_vfs_write_kretprobe,
                                                                        true, function_list[NETDATA_VFS_WRITE]);
    ret = libbpf_get_error(obj->links.netdata_vfs_write_kretprobe);
    if (ret)
        return -1;

    obj->links.netdata_vfs_writev_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_vfs_writev_kprobe,
                                                                      false, function_list[NETDATA_VFS_WRITEV]);
    ret = libbpf_get_error(obj->links.netdata_vfs_writev_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_vfs_writev_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_vfs_writev_kretprobe,
                                                                         true, function_list[NETDATA_VFS_WRITEV]);
    ret = libbpf_get_error(obj->links.netdata_vfs_writev_kretprobe);
    if (ret)
        return -1;

    obj->links.netdata_vfs_read_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_vfs_read_kprobe,
                                                                    false, function_list[NETDATA_VFS_READ]);
    ret = libbpf_get_error(obj->links.netdata_vfs_read_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_vfs_read_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_vfs_read_kretprobe,
                                                                       true, function_list[NETDATA_VFS_READ]);
    ret = libbpf_get_error(obj->links.netdata_vfs_read_kretprobe);
    if (ret)
        return -1;

    obj->links.netdata_vfs_readv_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_vfs_readv_kprobe,
                                                                     false, function_list[NETDATA_VFS_READV]);
    ret = libbpf_get_error(obj->links.netdata_vfs_readv_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_vfs_readv_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_vfs_readv_kretprobe,
                                                                        true, function_list[NETDATA_VFS_READV]);
    ret = libbpf_get_error(obj->links.netdata_vfs_readv_kretprobe);
    if (ret)
        return -1;
 
    obj->links.netdata_vfs_unlink_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_vfs_unlink_kprobe,
                                                                      false, function_list[NETDATA_VFS_UNLINK]);
    ret = libbpf_get_error(obj->links.netdata_vfs_unlink_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_vfs_unlink_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_vfs_unlink_kretprobe,
                                                                         true, function_list[NETDATA_VFS_UNLINK]);
    ret = libbpf_get_error(obj->links.netdata_vfs_unlink_kretprobe);
    if (ret)
        return -1;

    obj->links.netdata_vfs_fsync_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_vfs_fsync_kprobe,
                                                                     false, function_list[NETDATA_VFS_FSYNC]);
    ret = libbpf_get_error(obj->links.netdata_vfs_fsync_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_vfs_fsync_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_vfs_fsync_kretprobe,
                                                                        true, function_list[NETDATA_VFS_FSYNC]);
    ret = libbpf_get_error(obj->links.netdata_vfs_fsync_kretprobe);
    if (ret)
        return -1;

    obj->links.netdata_vfs_open_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_vfs_open_kprobe,
                                                                    false, function_list[NETDATA_VFS_OPEN]);
    ret = libbpf_get_error(obj->links.netdata_vfs_open_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_vfs_open_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_vfs_open_kretprobe,
                                                                       true, function_list[NETDATA_VFS_OPEN]);
    ret = libbpf_get_error(obj->links.netdata_vfs_open_kretprobe);
    if (ret)
        return -1;

    obj->links.netdata_vfs_create_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_vfs_create_kprobe,
                                                                      false, function_list[NETDATA_VFS_OPEN]);
    ret = libbpf_get_error(obj->links.netdata_vfs_create_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_vfs_create_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_vfs_create_kretprobe,
                                                                         true, function_list[NETDATA_VFS_OPEN]);
    ret = libbpf_get_error(obj->links.netdata_vfs_create_kretprobe);
    if (ret)
        return -1;
 
    return 0;
}

static inline int ebpf_load_and_attach(struct vfs_bpf *obj, int selector)
{
    if (!selector) { // trampoline
        ebpf_disable_probes(obj);
#if (MY_LINUX_VERSION_CODE <= KERNEL_VERSION(5,6,0))
        ebpf_disable_specific_trampoline(obj);
#endif

        ebpf_set_trampoline_target(obj);
    } else if (selector == NETDATA_MODE_PROBE) {  // kprobe
        ebpf_disable_trampoline(obj);
    }

    int ret = vfs_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    }

    if (!selector) {
        ret = vfs_bpf__attach(obj);
    } else {
        ret = ebpf_attach_probes(obj);
    }
    
    if (!ret) {
        fprintf(stdout, "VFS loaded with success\n");
    }

    return ret;
}

static int vfs_read_apps_array(int fd, int ebpf_nprocs, uint32_t my_pid)
{
    struct netdata_vfs_stat_t *stored = calloc((size_t)ebpf_nprocs, sizeof(struct netdata_vfs_stat_t));
    if (!stored)
        return 2;

    uint64_t counter = 0;
    if (!bpf_map_lookup_elem(fd, &my_pid, stored)) {
        int j;
        for (j = 0; j < ebpf_nprocs; j++) {
            counter += (stored[j].pid_tgid + stored[j].pid + stored[j].write_call + stored[j].writev_call +
                        stored[j].read_call + stored[j].readv_call + stored[j].unlink_call + stored[j].fsync_call +
                        stored[j].open_call + stored[j].create_call + stored[j].write_bytes + stored[j].writev_bytes +
                        stored[j].readv_bytes + stored[j].read_bytes + stored[j].write_err + stored[j].writev_err +
                        stored[j].read_err + stored[j].readv_err + stored[j].unlink_err + stored[j].fsync_err +
                        stored[j].fsync_err + stored[j].open_err + stored[j].create_err);
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

    struct netdata_vfs_stat_t stats = { .pid_tgid = (__u64)pid, .pid = pid, .pad = 0, .write_call = 1,
                                        .writev_call = 1, .read_call = 1, .readv_call = 1, .unlink_call = 1,
                                        .fsync_call = 1, .open_call = 1, .create_call = 1, .write_bytes = 1,
                                        .writev_bytes = 1, .readv_bytes = 1, .read_bytes = 1, .write_err = 1,
                                        .writev_err = 1, .read_err = 1, .readv_err = 1, .unlink_err = 1,
                                        .fsync_err = 1, .open_err = 1, .create_err = 1 };

    uint32_t idx = (uint32_t)pid;
    int ret = bpf_map_update_elem(apps, &idx, &stats, 0);
    if (ret)
        fprintf(stderr, "Cannot insert value to apps table.");

    return pid;
}

static int ebpf_vfs_tests(int selector)
{
    struct vfs_bpf *obj = NULL;
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);

    obj = vfs_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");

        return 2;
    }

    int ret = ebpf_load_and_attach(obj, selector);
    if (!ret) {
        int fd = bpf_map__fd(obj->maps.vfs_ctrl);
        update_controller_table(fd);

        fd = bpf_map__fd(obj->maps.tbl_vfs_stats);
        int fd2 = bpf_map__fd(obj->maps.tbl_vfs_pid);
        pid_t my_pid = ebpf_update_tables(fd, fd2);

        ret =  ebpf_read_global_array(fd, ebpf_nprocs, NETDATA_VFS_COUNTER);
        if (!ret) {
            ret = vfs_read_apps_array(fd2, ebpf_nprocs, (uint32_t)my_pid);
            if (ret)
                fprintf(stderr, "Cannot read apps table\n");
        } else
            fprintf(stderr, "Cannot read global table\n");
    } else
        fprintf(stderr ,"%s", NETDATA_CORE_DEFAULT_ERROR);

    vfs_bpf__destroy(obj);

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
                          ebpf_print_help(argv[0], "vfs", 1);
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
            selector = ebpf_find_functions(bf, selector, function_list, NETDATA_VFS_END_LIST);
            btf__free(bf);
        }
    }

    return ebpf_vfs_tests(selector);
}

