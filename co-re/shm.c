#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include <sys/ipc.h>
#include <sys/shm.h>

#include "netdata_tests.h"
#include "netdata_shm.h"

#include "shm.skel.h"

char *syscalls[NETDATA_SHM_END] = { "__x64_sys_shmget",
                                    "__x64_sys_shmat",
                                    "__x64_sys_shmdt",
                                    "__x64_sys_shmctl"
                                    };

static void ebpf_disable_tracepoint(struct shm_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_syscall_shmget, false);
    bpf_program__set_autoload(obj->progs.netdata_syscall_shmat, false);
    bpf_program__set_autoload(obj->progs.netdata_syscall_shmdt, false);
    bpf_program__set_autoload(obj->progs.netdata_syscall_shmctl, false);
}

static void ebpf_disable_kprobe(struct shm_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_shmget_probe, false);
    bpf_program__set_autoload(obj->progs.netdata_shmat_probe, false);
    bpf_program__set_autoload(obj->progs.netdata_shmdt_probe, false);
    bpf_program__set_autoload(obj->progs.netdata_shmctl_probe, false);
}

static void ebpf_disable_trampoline(struct shm_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_shmget_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_shmat_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_shmdt_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_shmctl_fentry, false);
}

static int ebpf_attach_kprobe(struct shm_bpf *obj)
{
    obj->links.netdata_shmget_probe = bpf_program__attach_kprobe(obj->progs.netdata_shmget_probe,
                                                                 false, syscalls[NETDATA_KEY_SHMGET_CALL]);
    int ret = libbpf_get_error(obj->links.netdata_shmget_probe);
    if (ret)
        return -1;

    obj->links.netdata_shmat_probe = bpf_program__attach_kprobe(obj->progs.netdata_shmat_probe,
                                                                false, syscalls[NETDATA_KEY_SHMAT_CALL]);
    ret = libbpf_get_error(obj->links.netdata_shmat_probe);
    if (ret)
        return -1;

    obj->links.netdata_shmdt_probe = bpf_program__attach_kprobe(obj->progs.netdata_shmdt_probe,
                                                                false, syscalls[NETDATA_KEY_SHMDT_CALL]);
    ret = libbpf_get_error(obj->links.netdata_shmdt_probe);
    if (ret)
        return -1;

    obj->links.netdata_shmctl_probe = bpf_program__attach_kprobe(obj->progs.netdata_shmctl_probe,
                                                                false, syscalls[NETDATA_KEY_SHMCTL_CALL]);
    ret = libbpf_get_error(obj->links.netdata_shmctl_probe);
    if (ret)
        return -1;

    return 0;
}

static void ebpf_set_trampoline_target(struct shm_bpf *obj)
{
    bpf_program__set_attach_target(obj->progs.netdata_shmget_fentry, 0,
                                   syscalls[NETDATA_KEY_SHMGET_CALL]);

    bpf_program__set_attach_target(obj->progs.netdata_shmat_fentry, 0,
                                   syscalls[NETDATA_KEY_SHMAT_CALL]);

    bpf_program__set_attach_target(obj->progs.netdata_shmdt_fentry, 0,
                                   syscalls[NETDATA_KEY_SHMDT_CALL]);

    bpf_program__set_attach_target(obj->progs.netdata_shmctl_fentry, 0,
                                   syscalls[NETDATA_KEY_SHMCTL_CALL]);

}

static inline int ebpf_load_and_attach(struct shm_bpf *obj, int selector)
{
    if (!selector) { // trampoline
        ebpf_disable_tracepoint(obj);
        ebpf_disable_kprobe(obj);

        ebpf_set_trampoline_target(obj);
    } else if (selector == 1) { // kprobe
        ebpf_disable_tracepoint(obj);
        ebpf_disable_trampoline(obj);
    } else { // tracepoint
        ebpf_disable_kprobe(obj);
        ebpf_disable_trampoline(obj);
    }

    int ret = shm_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    }

    if (selector != 1) // Not kprobe
        ret = shm_bpf__attach(obj);
    else
        ret = ebpf_attach_kprobe(obj);

    if (!ret) {
        char *method = ebpf_select_type(selector);
        fprintf(stdout, "%s loaded with success\n", method);
    }

    return ret;
}

int call_syscalls()
{
#define SHMSZ   27
    // Copied and adapt from https://github.com/netdata/netdata/pull/11560#issuecomment-927613811
    key_t name = 5678;

    int shmid = shmget(name, SHMSZ, IPC_CREAT | 0666);
    if (shmid < 0)
         return 2;

    sleep(1);

    char *shm = shmat(shmid, NULL, 0);
    if (shm == (char *) -1) {
        perror("shmat");
        return 2;
    }

    char c, *s = shm;
    for (c = 'a'; c <= 'z'; c++)
        *s++ = c;
    *s = 0;

    sleep(1);

    struct shmid_ds dsbuf;
    if ((shmctl(shmid, IPC_STAT, &dsbuf)) == -1) {
        perror("shmctl");
        return 2;
    }

    if ((shmdt(shm)) == -1) {
        perror("shmdt");
        return 2;
    }

    return 0;
}

static int shm_read_apps_array(int fd, int ebpf_nprocs)
{
    netdata_shm_t *stored = calloc((size_t)ebpf_nprocs, sizeof(netdata_shm_t));
    if (!stored)
        return 2;

    uint32_t idx = (uint32_t) getpid();
    uint64_t counter = 0;
    if (!bpf_map_lookup_elem(fd, &idx, stored)) {
        int j;
        for (j = 0; j < ebpf_nprocs; j++) {
            counter += (stored[j].get + stored[j].at + stored[j].dt +stored[j].ctl);
        }
    }

    free(stored);

    if (counter >= 4) {
        fprintf(stdout, "Apps data stored with success\n");
        return 0;
    }

    return 2;
}

int ebpf_shm_tests(struct btf *bf, int selector)
{
    struct shm_bpf *obj = NULL;
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);

    if (bf)
        selector = ebpf_find_functions(bf, selector, syscalls, NETDATA_SHM_END);

    obj = shm_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");

        return 2;
    }

    int ret = ebpf_load_and_attach(obj, selector);
    if (!ret) {
        int fd = bpf_map__fd(obj->maps.shm_ctrl);
        update_controller_table(fd);

        ret = call_syscalls();
        if (!ret) {
            fd = bpf_map__fd(obj->maps.tbl_shm);
            ret = ebpf_read_global_array(fd, ebpf_nprocs, NETDATA_SHM_END);
            if (!ret) {
                fd = bpf_map__fd(obj->maps.tbl_pid_shm);
                ret = shm_read_apps_array(fd, ebpf_nprocs);
            }
        }
    } else
        fprintf(stderr ,"%s", NETDATA_CORE_DEFAULT_ERROR);

    shm_bpf__destroy(obj);

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

    // use trampoline as default
    int selector = NETDATA_MODE_TRAMPOLINE;
    int option_index = 0;
    while (1) {
        int c = getopt_long(argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h': {
                          ebpf_print_help(argv[0], "shared_memory", 1);
                          exit(0);
                      }
            case 'p': {
                          selector = NETDATA_MODE_PROBE;
                          break;
                      }
            case 'r': {
                          selector = NETDATA_MODE_TRACEPOINT;
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
    }

    ret = ebpf_shm_tests(bf, selector);

    if (bf)
        btf__free(bf);

    return 0;
}

