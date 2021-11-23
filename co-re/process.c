#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <sys/wait.h>

#include <linux/version.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include "netdata_tests.h"
#include "netdata_process.h"

#include "process.skel.h"

static void ebpf_disable_probes(struct process_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_release_task_probe, false);
    bpf_program__set_autoload(obj->progs.netdata_do_fork_probe, false);
    bpf_program__set_autoload(obj->progs.netdata_kernel_clone_probe, false);
}

static void ebpf_disable_tracepoints(struct process_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_clone_exit, false);
    bpf_program__set_autoload(obj->progs.netdata_clone3_exit, false);
    bpf_program__set_autoload(obj->progs.netdata_fork_exit, false);
    bpf_program__set_autoload(obj->progs.netdata_vfork_exit, false);
}

static void ebpf_disable_trampoline(struct process_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_release_task_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_clone_fexit, false);
    bpf_program__set_autoload(obj->progs.netdata_clone3_fexit, false);
}

static void ebpf_set_trampoline_target(struct process_bpf *obj)
{
    bpf_program__set_attach_target(obj->progs.netdata_release_task_fentry, 0,
                                   "release_task");

    bpf_program__set_attach_target(obj->progs.netdata_clone_fexit, 0,
                                   "__x64_sys_clone");

    bpf_program__set_attach_target(obj->progs.netdata_clone3_fexit, 0,
                                   "__x64_sys_clone3");
}

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(5,3,0))
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8f6ccf6159aed1f04c6d179f61f6fb2691261e84
static inline void ebpf_disable_clone3(struct process_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_clone3_exit, false);
    bpf_program__set_autoload(obj->progs.netdata_clone3_fexit, false);
}
#endif

static inline int ebpf_load_and_attach(struct process_bpf *obj, int selector)
{
    if (!selector) { // trampoline
        ebpf_disable_probes(obj);
        ebpf_disable_tracepoints(obj);

        ebpf_set_trampoline_target(obj);
    } else if (selector == NETDATA_MODE_PROBE) {  // kprobe
        ebpf_disable_tracepoints(obj);
        ebpf_disable_trampoline(obj);

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(5,9,16))
    bpf_program__set_autoload(obj->progs.netdata_kernel_clone_probe, false);
#else
    bpf_program__set_autoload(obj->progs.netdata_do_fork_probe, false);
#endif        
    } else { // tracepoint
        ebpf_disable_probes(obj);
        ebpf_disable_trampoline(obj);
    }

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(5,3,0))
    ebpf_disable_clone3(obj);
#endif

    int ret = process_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    }

    ret = process_bpf__attach(obj);

    if (!ret) {
        fprintf(stdout, "Process loaded with success\n");
    }

    return ret;
}

static pid_t ebpf_create_threads()
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("Fork");
        return 0;
    } else if (!pid) {
        fprintf(stdout, "I'm the child.\n");
        sleep(1);
        exit(0);
    } else {
        fprintf(stdout, "I'm a proud dad!\n");
        wait(NULL);
    }

    return pid;
}

static int process_read_specific_app(struct netdata_pid_stat_t *stored, int fd, int ebpf_nprocs, uint32_t idx)
{
    uint64_t counter = 0;
    if (!bpf_map_lookup_elem(fd, &idx, stored)) {
        int j;
        for (j = 0; j < ebpf_nprocs; j++) {
            counter += (stored[j].exit_call + stored[j].release_call +
                        stored[j].create_process +stored[j].create_thread);
        }
    }

    return counter;
}

static int process_read_apps_array(int fd, int ebpf_nprocs, uint32_t child)
{
    struct netdata_pid_stat_t *stored = calloc((size_t)ebpf_nprocs, sizeof(struct netdata_pid_stat_t));
    if (!stored)
        return 2;

    uint32_t my_pid = (uint32_t) getpid();

    uint64_t counter = 0;
    counter += process_read_specific_app(stored, fd, ebpf_nprocs, my_pid);
    memset(stored, 0, (size_t)ebpf_nprocs * sizeof(struct netdata_pid_stat_t));
    counter += process_read_specific_app(stored, fd, ebpf_nprocs, child);

    free(stored);

    if (counter) {
        fprintf(stdout, "Apps data stored with success\n");
        return 0;
    }

    return 2;
}


static int ebpf_process_tests(int selector)
{
    struct process_bpf *obj = NULL;
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);

    obj = process_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");

        return 2;
    }

    int ret = ebpf_load_and_attach(obj, selector);
    if (!ret) {
        int fd = bpf_map__fd(obj->maps.process_ctrl);
        update_controller_table(fd);

        pid_t child = ebpf_create_threads();
        // Wait data from more processes
        sleep(10);

        fd = bpf_map__fd(obj->maps.tbl_total_stats);
        ret =  ebpf_read_global_array(fd, ebpf_nprocs, NETDATA_GLOBAL_COUNTER);
        if (!ret) {
            fd = bpf_map__fd(obj->maps.tbl_pid_stats);
            ret = process_read_apps_array(fd, ebpf_nprocs, (uint32_t)child);
        }
    }

    process_bpf__destroy(obj);

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
                          ebpf_print_help(argv[0], "mount", 1);
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

    return ebpf_process_tests(selector);
}

