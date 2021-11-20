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

static void ebpf_disable_tracepoint(struct shm_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_syscall_shmget, false);
    bpf_program__set_autoload(obj->progs.netdata_syscall_shmat, false);
    bpf_program__set_autoload(obj->progs.netdata_syscall_shmdt, false);
    bpf_program__set_autoload(obj->progs.netdata_syscall_shmctl, false);
}

static inline int ebpf_load_and_attach(struct shm_bpf *obj, int selector)
{
    if (!selector) { // trampoline
        ebpf_disable_tracepoint(obj);
    } else if (selector == 1) { // kprobe
        ebpf_disable_tracepoint(obj);
    } else { // tracepoint
    }

    int ret = shm_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    }

    if (selector != 1) // Not kprobe
        ret = shm_bpf__attach(obj);

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

static int shm_read_global_array(int fd, int ebpf_nprocs)
{
    uint64_t *stored = calloc((size_t)ebpf_nprocs, sizeof(uint64_t));
    if (!stored)
        return 2;

    size_t length = (size_t)ebpf_nprocs * sizeof(uint64_t);
    uint32_t idx;
    uint64_t counter = 0;
    for (idx = 0; idx < NETDATA_SHM_END; idx++) {
        if (!bpf_map_lookup_elem(fd, &idx, stored)) {
            int j;
            for (j = 0; j < ebpf_nprocs; j++) {
                counter += stored[j];
            }
        }

        memset(stored, 0, length);
    }

    free(stored);

    if (counter >= 4) {
        fprintf(stdout, "Global data stored with success\n");
        return 0;
    }

    return 2;
}

int ebpf_shm_tests(int selector)
{
    struct shm_bpf *obj = NULL;
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);

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
            int fd = bpf_map__fd(obj->maps.tbl_shm);
            ret = shm_read_global_array(fd, ebpf_nprocs);
        }
    }

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
    int selector = 0;
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
    
    struct btf *bf = NULL;
    if (!selector) {
        bf = netdata_parse_btf_file((const char *)NETDATA_BTF_FILE);
    }

    ret = ebpf_shm_tests(selector);

    if (bf)
        btf__free(bf);

    return 0;
}
