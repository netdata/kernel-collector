#include <assert.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <dlfcn.h>
#include <ctype.h>
#include <dirent.h>
#include <time.h>

#include <sys/time.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "perf-sys.h"

#include <sys/ioctl.h>

#include "process_user.h"

#define NETDATA_MAX_PROCESSOR 512
#define NETDATA_DEBUGFS "/sys/kernel/debug/tracing/"

void *libnetdata = NULL; 
int (*load_bpf_file)(char *, int) = NULL;
int (*bpf_map_lookup_elem)(int, const void *, void *);
int *map_fd = NULL;

static int thread_finished = 0;
static int close_plugin = 0;
static int mykernel = 0;

static long nprocs;

int event_pid = 0;
netdata_ebpf_events_t collector_events[] = {
        { .type = 'p', .name = "vfs_write" },
        { .type = 'r', .name = "vfs_write" },
        { .type = 'p', .name = "vfs_writev" },
        { .type = 'r', .name = "vfs_writev" },
        { .type = 'p', .name = "vfs_read" },
        { .type = 'r', .name = "vfs_read" },
        { .type = 'p', .name = "vfs_readv" },
        { .type = 'r', .name = "vfs_readv" },
        { .type = 'p', .name = "do_sys_open" },
        { .type = 'r', .name = "do_sys_open" },
        { .type = 'p', .name = "vfs_unlink" },
        { .type = 'r', .name = "vfs_unlink" },
        { .type = 'p', .name = "_do_fork" },
        { .type = 'r', .name = "_do_fork" },
        { .type = 'p', .name = "__close_fd" },
        { .type = 'r', .name = "__close_fd" },
        { .type = 0, .name = NULL }
};

static int pmu_fd[NETDATA_MAX_PROCESSOR];
static struct perf_event_mmap_page *headers[NETDATA_MAX_PROCESSOR];

static char plugin_dir[1024];

static int clean_kprobe_event(char *filename, char *father_pid, netdata_ebpf_events_t *ptr) {
    int fd =  open(filename, O_WRONLY | O_APPEND, 0);
    if (fd < 0) {
        fprintf(stderr, "Cannot open %s : %s\n", filename, strerror(errno));
        return 1;
    }

    char cmd[1024];
    int length = sprintf(cmd, "-:kprobes/%c_netdata_%s_%s", ptr->type, ptr->name, father_pid);
    int ret = 0;
    if (length > 0) {
        ssize_t written = write(fd, cmd, strlen(cmd));
        if (written < 0) {
            fprintf(stderr
                    , "Cannot remove the event (%d, %d) '%s' from %s : %s\n"
                    , getppid(), getpid(), cmd, filename, strerror((int)errno));
            ret = 1;
        }
    }

    close(fd);

    return ret;
}

int clean_kprobe_events(int pid, netdata_ebpf_events_t *ptr) {
    char filename[FILENAME_MAX +1];
    snprintf(filename, FILENAME_MAX, "%s%s", NETDATA_DEBUGFS, "kprobe_events");

    char removeme[16];
    snprintf(removeme, 15,"%d", pid);

    int i;
    for (i = 0 ; ptr[i].name ; i++) {
        if (clean_kprobe_event(filename, removeme, &ptr[i])) {
            break;
        }
    }

    return 0;
}

static void int_exit(int sig)
{
    if (libnetdata) {
        dlclose(libnetdata);
    }

    if (event_pid) {
        int ret = fork();
        if (ret < 0) //error
            sig = 6;
        else if (!ret) { //child
            int i;
            for ( i=getdtablesize(); i>=0; --i)
                close(i);

            int fd = open("/dev/null",O_RDWR, 0);
            if (fd != -1) {
                dup2 (fd, STDIN_FILENO);
                dup2 (fd, STDOUT_FILENO);
                dup2 (fd, STDERR_FILENO);

                if (fd > 2)
                    close (fd);
            }

            int sid = setsid();
            if(sid >= 0) {
                sleep(1);
                clean_kprobe_events(event_pid, collector_events);
            } else {
                fprintf(stderr,"Cannot become session id leader, so I won't try to clean kprobe_events.\n");
                sig = 7;
            }
        } else { //parent
            exit(0);
        }
    }

    exit(sig);
}

int get_kernel_version() {
    char major[16], minor[16], patch[16];
    char ver[256];
    char *version = ver;

    int fd = open("/proc/sys/kernel/osrelease", O_RDONLY);
    if (fd < 0)
        return -1;

    ssize_t len = read(fd, version, sizeof(version));
    if (len < 0)
        return -1;

    close(fd);

    char *move = major;
    while (*version && *version != '.') *move++ = *version++;
    *move = '\0';

    version++;
    move = minor;
    while (*version && *version != '.') *move++ = *version++;
    *move = '\0';

    if (*version)
        version++;
    move = patch;
    while (*version) *move++ = *version++;
    *move = '\0';

    return ((int)(strtol(major, NULL, 10)*65536) + (int)(strtol(minor, NULL, 10)*256) + (int)strtol(patch, NULL, 10));
}

static int has_ebpf_kernel_version(int version) {
    return (version >= 266752); //4.18.0
}

int has_condition_to_run(int version) {
    if(!has_ebpf_kernel_version(version))
        return 0;

    return 1;
}

static void build_complete_path(char *out, size_t length,char *path, char *filename) {
    if(path){
        snprintf(out, length, "%s/%s", path, filename);
    } else {
        snprintf(out, length, "%s", filename);
    }
}

static int ebpf_load_libraries()
{
    char *err = NULL;
    char lpath[4096];

    build_complete_path(lpath, 4096, plugin_dir, "libnetdata_ebpf.so");
    libnetdata = dlopen(lpath, RTLD_LAZY);
    if (!libnetdata) {
        return -1;
    } else {
        load_bpf_file = dlsym(libnetdata, "load_bpf_file");
        if ((err = dlerror()) != NULL) {
            return -1;
        }

        map_fd =  dlsym(libnetdata, "map_fd");
        if ((err = dlerror()) != NULL) {
            return -1;
        }

        bpf_map_lookup_elem = dlsym(libnetdata, "bpf_map_lookup_elem");
        if ((err = dlerror()) != NULL) {
            return -1;
        }
    }

    return 0;
}

int process_load_ebpf()
{
    char lpath[4096];

    char *name = { "dlatency_process_kern.o" };

    build_complete_path(lpath, 4096, plugin_dir,  name);

    event_pid = getpid();
    if (load_bpf_file(lpath, event_pid) ) {
        return -1;
    }

    return 0;
}

void measure_latency( )
{
    netdata_latency_t *nl = (netdata_latency_t *)malloc(sizeof(netdata_latency_t)*nprocs);
    if(!nl) {
        fprintf(stderr,"Cannot allocate netdata latency structure\n");
        return;
    }

    netdata_latency_t results[NETDATA_MAX_MONITOR_VECTOR];
    memset(&results, 0, sizeof(results));
    uint64_t length;
    uint64_t counter;
    uint64_t total = 0;

    uint32_t i, j;
    int fd = map_fd[0];
    struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
    while (total <= 10000000) {
        total = 0;
        for (i = 0; i < 8; i++) {
            int test = bpf_map_lookup_elem(fd, &i, nl);

            if(!test) {
                counter = 0;
                length = 0;
                for (j = 0 ; j < nprocs; j++) {
                    counter += nl[j].counter;
                    length += nl[j].period;
                }

                total += counter;
                results[i].counter = counter;
                results[i].period = length;
            }
        }

        nanosleep(&ts, NULL);
    }

    fprintf(stdout, "|     Function     | Number of calls | Average Latency(ns) |\n");
    fprintf(stdout, "|------------------|-----------------|---------------------|\n");
    fprintf(stdout, "| %16s | %15lu | %19g |\n", collector_events[0].name, results[0].counter, (results[0].counter)?((double)results[0].period)/((double)results[0].counter):0);
    fprintf(stdout, "| %16s | %15lu | %19g |\n", collector_events[2].name, results[1].counter, (results[1].counter)?((double)results[1].period)/((double)results[1].counter):0);
    fprintf(stdout, "| %16s | %15lu | %19g |\n", collector_events[4].name, results[2].counter, (results[2].counter)?((double)results[2].period)/((double)results[2].counter):0);
    fprintf(stdout, "| %16s | %15lu | %19g |\n", collector_events[6].name, results[3].counter, (results[3].counter)?((double)results[3].period)/((double)results[3].counter):0);
    fprintf(stdout, "| %16s | %15lu | %19g |\n", collector_events[10].name, results[5].counter, (results[5].counter)?((double)results[5].period)/((double)results[5].counter):0);
    fprintf(stdout, "| %16s | %15lu | %19g |\n", collector_events[8].name, results[4].counter, (results[4].counter)?((double)results[4].period)/((double)results[4].counter):0);
    fprintf(stdout, "| %16s | %15lu | %19g |\n", collector_events[12].name, results[6].counter, (results[6].counter)?((double)results[6].period)/((double)results[6].counter):0);
    fprintf(stdout, "| %16s | %15lu | %19g |\n", collector_events[14].name, results[7].counter, (results[7].counter)?((double)results[7].period)/((double)results[7].counter):0);

    free(nl);
}

int main(int argc, char **argv)
{
    mykernel =  get_kernel_version();
    if(!has_condition_to_run(mykernel)) {
        return 1;
    }

    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);

    nprocs = sysconf(_SC_NPROCESSORS_ONLN);

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        return 2;
    }

    if (!getcwd(plugin_dir, 1023)) {
        return 3;
    }

    if(ebpf_load_libraries()) {
        int_exit(4);
    }

    if (process_load_ebpf()) {
        int_exit(5);
    }

    measure_latency();

    int_exit(0);

    return 0;
}
