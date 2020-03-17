#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <libgen.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/types.h>

#include "perf-sys.h"

#include <sys/ioctl.h>

#include "process_user.h"

#define NETDATA_MAX_PROCESSOR 512
#define NETDATA_DEBUGFS "/sys/kernel/debug/tracing/"

void* libnetdata = NULL;
int (*load_bpf_file)(char*, int) = NULL;
int (*set_bpf_perf_event)(int, int);
int (*perf_event_unmap)(struct perf_event_mmap_page*, size_t);
int (*perf_event_mmap_header)(int, struct perf_event_mmap_page**, int);
void (*netdata_perf_loop_multi)(int*, struct perf_event_mmap_page**, int, int*, int (*nsb)(void*, int), int);
int (*bpf_map_lookup_elem)(int, const void*, void*);
int* map_fd = NULL;

static int thread_finished = 0;
static int close_plugin = 0;
static int mykernel = 0;

int event_pid = 0;
int page_cnt = 8;
netdata_ebpf_events_t collector_events[] = {
   { .type = 'r', .name = "vfs_write" },
   { .type = 'r', .name = "vfs_writev" },
   { .type = 'r', .name = "vfs_read" },
   { .type = 'r', .name = "vfs_readv" },
   { .type = 'r', .name = "do_sys_open" },
   { .type = 'r', .name = "vfs_unlink" },
   { .type = 'p', .name = "do_exit" },
   { .type = 'p', .name = "release_task" },
   { .type = 'r', .name = "_do_fork" },
   { .type = 'r', .name = "__close_fd" },
   { .type = 'r', .name = "__x64_sys_clone" },
   { .type = 0, .name = NULL }
};

static int pmu_fd[NETDATA_MAX_PROCESSOR];
static struct perf_event_mmap_page* headers[NETDATA_MAX_PROCESSOR];

static char plugin_dir[1024];

/*
static int unmap_memory() {
    int nprocs = (int) sysconf(_SC_NPROCESSORS_ONLN);

    if (nprocs > NETDATA_MAX_PROCESSOR) {
        nprocs = NETDATA_MAX_PROCESSOR;
    }

    int i;
    int size = (int)sysconf(_SC_PAGESIZE)*(page_cnt + 1);
    for ( i = 0 ; i < nprocs ; i++ ) {
        if (headers[i])
        {
            if (perf_event_unmap(headers[i], size) < 0) {
                fprintf(stderr,"[EBPF PROCESS] CANNOT unmap headers.\n");
                return -1;
            }
        }

        close(pmu_fd[i]);
    }

    return 0;
}
*/

static int clean_kprobe_event(char* filename, char* father_pid, netdata_ebpf_events_t* ptr)
{
   int fd = open(filename, O_WRONLY | O_APPEND, 0);
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
         fprintf(stderr, "Cannot remove the event (%d, %d) '%s' from %s : %s\n", getppid(), getpid(), cmd, filename, strerror((int)errno));
         ret = 1;
      }
   }

   close(fd);

   return ret;
}

int clean_kprobe_events(int pid, netdata_ebpf_events_t* ptr)
{
   char filename[FILENAME_MAX + 1];
   snprintf(filename, FILENAME_MAX, "%s%s", NETDATA_DEBUGFS, "kprobe_events");

   char removeme[16];
   snprintf(removeme, 15, "%d", pid);

   int i;
   for (i = 0; ptr[i].name; i++) {
      if (clean_kprobe_event(filename, removeme, &ptr[i])) {
         break;
      }
   }

   return 0;
}

static void int_exit(int sig)
{
   // unmap_memory();

   if (libnetdata) {
      dlclose(libnetdata);
   }

   if (event_pid) {
      int ret = fork();
      if (ret < 0) //error
         sig = 6;
      else if (!ret) { //child
         int i;
         for (i = getdtablesize(); i >= 0; --i)
            close(i);

         int fd = open("/dev/null", O_RDWR, 0);
         if (fd != -1) {
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);

            if (fd > 2)
               close(fd);
         }

         int sid = setsid();
         if (sid >= 0) {
            sleep(1);
            clean_kprobe_events(event_pid, collector_events);
         } else {
            fprintf(stderr, "Cannot become session id leader, so I won't try to clean kprobe_events.\n");
            sig = 7;
         }
      } else { //parent
         exit(0);
      }
   }

   exit(sig);
}

int get_kernel_version()
{
   char major[16], minor[16], patch[16];
   char ver[256];
   char* version = ver;

   int fd = open("/proc/sys/kernel/osrelease", O_RDONLY);
   if (fd < 0)
      return -1;

   ssize_t len = read(fd, version, sizeof(version));
   if (len < 0)
      return -1;

   close(fd);

   char* move = major;
   while (*version && *version != '.')
      *move++ = *version++;
   *move = '\0';

   version++;
   move = minor;
   while (*version && *version != '.')
      *move++ = *version++;
   *move = '\0';

   if (*version)
      version++;
   move = patch;
   while (*version)
      *move++ = *version++;
   *move = '\0';

   return ((int)(strtol(major, NULL, 10) * 65536) + (int)(strtol(minor, NULL, 10) * 256) + (int)strtol(patch, NULL, 10));
}

static int has_redhat_release()
{
    char out[256];
    int major,minor;
    FILE *fp = fopen("/etc/redhat-release", "r");
    
    if (fp) {
        fread(out, sizeof(char), 255, fp);
        fclose(fp);
        char *end = strchr(out, '.');
        char *start;
        if (end) {
            *end = 0x0;

            if (end > out) {
                start = end - 1;
            }

            major = strtol( start, NULL, 10);
            start = ++end;

            end++;
            if(end) {
                end = 0x00;
                minor = strtol( start, NULL, 10);
            } else {
                minor = -1;
            }
        } else {
            major = 0;
            minor = -1;
        }

        return ((major<<8) + minor);
    } else {
        return -1;
    }
}

static int has_ebpf_kernel_version(int version)
{
          //4.11.0 or RH > 7.5
   return (version >= 264960 || has_redhat_release() >= 1797);
}

int has_condition_to_run(int version)
{
   if (!has_ebpf_kernel_version(version))
      return 0;

   return 1;
}

static void build_complete_path(char* out, size_t length, char* path, char* filename)
{
   if (path) {
      snprintf(out, length, "%s/%s", path, filename);
   } else {
      snprintf(out, length, "%s", filename);
   }
}

static int ebpf_load_libraries()
{
   char* err = NULL;
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

      map_fd = dlsym(libnetdata, "map_fd");
      if ((err = dlerror()) != NULL) {
         return -1;
      }

      bpf_map_lookup_elem = dlsym(libnetdata, "bpf_map_lookup_elem");
      if ((err = dlerror()) != NULL) {
         return -1;
      }

      set_bpf_perf_event = dlsym(libnetdata, "set_bpf_perf_event");
      if ((err = dlerror()) != NULL) {
         return -1;
      }

      perf_event_unmap = dlsym(libnetdata, "perf_event_unmap");
      if ((err = dlerror()) != NULL) {
         return -1;
      }

      perf_event_mmap_header = dlsym(libnetdata, "perf_event_mmap_header");
      if ((err = dlerror()) != NULL) {
         return -1;
      }

      netdata_perf_loop_multi = dlsym(libnetdata, "netdata_perf_loop_multi");
      if ((err = dlerror()) != NULL) {
         return -1;
      }
   }

   return 0;
}

int process_load_ebpf()
{
   char lpath[4096];

   char* name = { "rnetdata_ebpf_process.o" };

   build_complete_path(lpath, 4096, plugin_dir, name);
   event_pid = getpid();
   if (load_bpf_file(lpath, event_pid)) {
      fprintf(stderr, "Cannot load the eBPF program (%d): %s\n", errno, lpath);
      return -1;
   }

   return 0;
}

/*
static int map_memory() {
    int nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);

    if (nprocs > NETDATA_MAX_PROCESSOR) {
        nprocs = NETDATA_MAX_PROCESSOR;
    }

    int i;
    for (i = 0; i < nprocs; i++) {
        pmu_fd[i] = set_bpf_perf_event(i, 2);

        if (perf_event_mmap_header(pmu_fd[i], &headers[i], page_cnt) < 0) {
            return -1;
        }
    }

    return 0;
}
*/

int main(int argc, char** argv)
{
   mykernel = get_kernel_version();
   if (!has_condition_to_run(mykernel)) {
      fprintf(stderr, "I cannot run on this kernel\n");
      return 1;
   }

   struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
   if (setrlimit(RLIMIT_MEMLOCK, &r)) {
      fprintf(stderr, "Cannot set limits\n");
      return 2;
   }

   page_cnt *= sysconf(_SC_NPROCESSORS_ONLN);
   if (!getcwd(plugin_dir, 1023)) {
      fprintf(stderr, "Cannot find current directory\n");
      return 3;
   }

   if (ebpf_load_libraries()) {
      fprintf(stderr, "Cannot load libnetdata_ebpf.so\n");
      int_exit(4);
   }

   if (process_load_ebpf()) {
      int_exit(5);
   }

   /*
    if (map_memory()) {
        fprintf(stderr,"Cannot map memory\n");
        int_exit(6);
    }
    */

   int_exit(0);

   return 0;
}
