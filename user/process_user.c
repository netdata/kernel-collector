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

#include <sys/ioctl.h>

#include "process_user.h"

#define NETDATA_MAX_PROCESSOR 512
#define NETDATA_DEBUGFS "/sys/kernel/debug/tracing/"

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

   int_exit(0);

   return 0;
}
