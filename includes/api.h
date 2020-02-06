#ifndef KPROBE_STAT_USER
# define KPROBE_STAT_USER 1

# include <stdio.h>
# include <stdint.h>
# include <dlfcn.h>

/*
int test_bpf_perf_event(int cpu);
void my_perf_loop_multi(int *pmu_fds, struct perf_event_mmap_page **headers, int numprocs, int *killme, int (*print_bpf_output)(void *, int));
*/

typedef struct {
    void *libnetdata; 
    int (*load_bpf_file)(char *);
    int (*test_bpf_perf_event)(int);
    int (*perf_event_mmap)(int);
    int (*perf_event_mmap_header)(int, struct perf_event_mmap_page **);
    void (*netdata_perf_loop_multi)(int *, struct perf_event_mmap_page **, int, int *, int (*nsb)(void *, int));
} netdata_ebpf_lib_t;

#endif
