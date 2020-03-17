#include <assert.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "perf-sys.h"
#include "trace_helpers.h"
#include "api.h"

#include "bpf/bpf.h"
#include "bpf_load.h"

int set_bpf_perf_event(int cpu, int map)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,3,0)
    int pmu_fd;
    struct perf_event_attr attr = {
                .sample_type = PERF_SAMPLE_RAW,
                .type = PERF_TYPE_SOFTWARE,
                .config = PERF_COUNT_SW_BPF_OUTPUT,
                .sample_period = 1, //NEW
                .wakeup_events = 1 //NEW
    };

    //pmu_fd = sys_perf_event_open(&attr, -1, cpu, -1, 0);// attr, pid, cpu, group id, flags
    pmu_fd = sys_perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC); //attr, pid, cpu, group id, flags

    int key = cpu;
    assert(pmu_fd >= 0);
    assert(bpf_map_update_elem(map_fd[map], &key, &pmu_fd, BPF_ANY) == 0);
    ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0);

    return pmu_fd;
#else
    return -1;
#endif
}

void netdata_perf_loop_multi(int *pmu_fds, struct perf_event_mmap_page **headers, int numprocs, int *killme, int (*print_bpf_output)(void *, int), int page_cnt)
{
    perf_event_poller_multi(pmu_fds, headers, numprocs, print_bpf_output, killme, page_cnt);
}
