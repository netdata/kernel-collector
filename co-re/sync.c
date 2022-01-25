#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include "netdata_tests.h"

#include <sys/mman.h>

#include "sync.skel.h"

enum netdata_sync_enum {
    NETDATA_SYNCFS_SYSCALL,
    NETDATA_MSYNC_SYSCALL,
    NETDATA_SYNC_FILE_RANGE_SYSCALL,
    NETDATA_FSYNC_SYSCALL,
    NETDATA_FDATASYNC_SYSCALL,
    NETDATA_SYNC_SYSCALL,

    NETDATA_END_SYNC_ENUM
};

static char *ebpf_sync_syscall[] = {
    "__x64_sys_syncfs",
    "__x64_sys_msync",
    "__x64_sys_sync_file_range",
    "__x64_sys_fsync",
    "__x64_sys_fdatasync",
    "__x64_sys_sync"
};

char *filename = { "useless_data.txt" };

/****************************************************************************************
 *
 *                                 COMMON FUNCTIONS
 *
 ***************************************************************************************/ 

static inline void ebpf_disable_local_tracepoints(struct sync_bpf *obj, enum netdata_sync_enum idx)
{
    if (idx != NETDATA_SYNCFS_SYSCALL )
        bpf_program__set_autoload(obj->progs.netdata_syncfs_entry, false);

    if (idx != NETDATA_MSYNC_SYSCALL)
        bpf_program__set_autoload(obj->progs.netdata_msync_entry, false);

    if (idx != NETDATA_SYNC_FILE_RANGE_SYSCALL)
        bpf_program__set_autoload(obj->progs.netdata_sync_file_range_entry, false);

    if (idx != NETDATA_FSYNC_SYSCALL)
        bpf_program__set_autoload(obj->progs.netdata_fsync_entry, false);

    if (idx != NETDATA_FDATASYNC_SYSCALL)
        bpf_program__set_autoload(obj->progs.netdata_fdatasync_entry, false);

    if (idx != NETDATA_SYNC_SYSCALL)
        bpf_program__set_autoload(obj->progs.netdata_sync_entry, false);
}

static inline int ebpf_load_and_attach(struct sync_bpf *obj, int selector, enum netdata_sync_enum idx)
{
    char *name = ebpf_sync_syscall[idx];
    if (!selector) { // trampoline
        bpf_program__set_autoload(obj->progs.netdata_sync_kprobe, false);
        ebpf_disable_local_tracepoints(obj, NETDATA_END_SYNC_ENUM);

        bpf_program__set_attach_target(obj->progs.netdata_sync_fentry, 0,
                                       name);
    } else if (selector == 1) { // kprobe
        ebpf_disable_local_tracepoints(obj, NETDATA_END_SYNC_ENUM);

        bpf_program__set_autoload(obj->progs.netdata_sync_fentry, false);
    } else { // tracepoint
        bpf_program__set_autoload(obj->progs.netdata_sync_kprobe, false);
        bpf_program__set_autoload(obj->progs.netdata_sync_fentry, false);

        ebpf_disable_local_tracepoints(obj, idx);
    }

    int ret = sync_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    }

    if (selector != 1) // Not kprobe
        ret = sync_bpf__attach(obj);
    else {
        obj->links.netdata_sync_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_sync_kprobe,
                                                                    false, name);
        ret = libbpf_get_error(obj->links.netdata_sync_kprobe);
    }

    if (!ret) {
        char *method = ebpf_select_type(selector);
        fprintf(stdout, "%s: %s loaded with success\n", name, method);
    }

     return ret;
}

/****************************************************************************************
 *
 *                              SYNCFS, FSYNC, FDATASYNC
 *
 ***************************************************************************************/ 

static void test_fcnt_synchronization(int (*fcnt)(int))
{
    int fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0660);
    if (fd < 0 ) {
        perror("Cannot open file descriptor");
        return;
    }

    int i;
    for ( i = 0 ; i < 1000; i++ )
        write(fd, "synchronize the data after this.", 32);

    fcnt(fd);
    close(fd);

    sleep(2);
}

static int common_fcnt_tests(int fd, int (*fcnt)(int)) {
    test_fcnt_synchronization(fcnt);

    uint32_t idx = 0;
    uint64_t stored;
    int ret;
    if (!bpf_map_lookup_elem(fd, &idx, &stored)) {
        if (stored) 
            ret = 0;
        else {
            ret = 4;
            fprintf(stderr, "Invalid data read from hash table");
        }
    } else {
        fprintf(stderr, "Cannot get data from hash table\n");
        ret = 3;
    }

    return ret;
}

static int ebpf_fcnt_tests(int (*fcnt)(int), enum netdata_sync_enum idx, int selector)
{
    struct sync_bpf *obj = NULL;

    obj = sync_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");

        return 2;
    }

    int ret = ebpf_load_and_attach(obj, selector, idx);
    if (!ret) {
        int fd = bpf_map__fd(obj->maps.tbl_sync) ;
        ret = common_fcnt_tests(fd, fcnt);
    } else
        fprintf(stderr ,"%s", NETDATA_CORE_DEFAULT_ERROR);

    sync_bpf__destroy(obj);

    return 0;
}

/****************************************************************************************
 *
 *                                      MSYNC
 *
 ***************************************************************************************/ 

// test based on IBM example https://www.ibm.com/support/knowledgecenter/en/ssw_ibm_i_71/apis/msync.htm
static void test_msync_synchronization()
{
    int pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize < 0) {
        perror("Cannot get page size");
        return;
    }

    int fd = open(filename, (O_CREAT | O_TRUNC | O_RDWR), (S_IRWXU | S_IRWXG | S_IRWXO));
    if (fd < 0 ) {
        perror("Cannot open file");
        return;
    }

    (void) lseek( fd, pagesize, SEEK_SET);
    ssize_t written = write(fd, " ", 1);
    if ( written != 1 ) {
        perror("Write error.");
        close(fd);
        return;
    }

    off_t my_offset = 0;
    void *address = mmap(NULL, pagesize, PROT_WRITE, MAP_SHARED, fd, my_offset);

    if ( address == MAP_FAILED ) {
        perror("Map error.");
        close(fd);
        return;
    }

    (void) strcpy((char*) address, "This is a text to test calls to msync");

    if ( msync(address, pagesize, MS_SYNC) < 0 ) {
        perror("msync failed with error:");
    }

    close(fd);
    sleep(2);
}

static int msync_tests(int fd) {
    test_msync_synchronization();

    uint32_t idx = 0;
    uint64_t stored;
    int ret;
    if (!bpf_map_lookup_elem(fd, &idx, &stored)) {
        if (stored) 
            ret = 0;
        else {
            ret = 3;
            fprintf(stderr, "Invalid data read from hash table");
        }
    } else {
        fprintf(stderr, "Cannot get data from hash table\n");
        ret = 3;
    }

    return ret;
}

static int ebpf_msync_tests(int selector)
{
    struct sync_bpf *obj = NULL;

    obj = sync_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");

        return 3;
    }

    int ret = ebpf_load_and_attach(obj, selector, NETDATA_MSYNC_SYSCALL);
    if (!ret) {
        int fd = bpf_map__fd(obj->maps.tbl_sync) ;
        ret = msync_tests(fd);
    } else
        fprintf(stderr, "Failed to attach BPF program\n");

    sync_bpf__destroy(obj);

    return 0;
}

/****************************************************************************************
 *
 *                                  SYNC_FILE_RANGE
 *
 ***************************************************************************************/ 

static void test_sync_file_range_synchronization()
{
    int fd = open (filename, O_WRONLY | O_CREAT | O_APPEND, 0660);
    if (fd < 0 ) {
        perror("Cannot get page size");
        return;
    }

    int i;
    size_t offset = 0;
    for ( i = 0 ; i < 1000; i++ )  {
        size_t length = 23;
        write(fd, "Testing one more syscall", length);
        sync_file_range(fd, offset, length, SYNC_FILE_RANGE_WRITE);
        offset += length;
    }

    close(fd);
    sleep(2);
}

static int sync_file_range_tests(int fd) {
    test_sync_file_range_synchronization();

    uint32_t idx = 0;
    uint64_t stored;
    int ret;
    if (!bpf_map_lookup_elem(fd, &idx, &stored)) {
        if (stored) 
            ret = 0;
        else {
            ret = 4;
            fprintf(stderr, "Invalid data read from hash table");
        }
    } else {
        fprintf(stderr, "Cannot get data from hash table\n");
        ret = 4;
    }

    return ret;
}

static int ebpf_sync_file_range_tests(int selector)
{
    struct sync_bpf *obj = NULL;

    obj = sync_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");

        return 2;
    }

    int ret = ebpf_load_and_attach(obj, selector, NETDATA_SYNC_FILE_RANGE_SYSCALL);
    if (!ret) {
        int fd = bpf_map__fd(obj->maps.tbl_sync) ;
        ret = sync_file_range_tests(fd);
    } else
        fprintf(stderr, "Failed to attach BPF program\n");

    sync_bpf__destroy(obj);

    return 0;
}

/****************************************************************************************
 *
 *                              SYNC
 *
 ***************************************************************************************/

static int sync_tests(int fd) {
    sync();
    sleep(2);

    uint32_t idx = 0;
    uint64_t stored;
    int ret;
    if (!bpf_map_lookup_elem(fd, &idx, &stored)) {
        if (stored)
            ret = 0;
        else {
            ret = 5;
            fprintf(stderr, "Invalid data read from hash table");
        }
    } else {
        fprintf(stderr, "Cannot get data from hash table\n");
        ret = 5;
    }

    return ret;
}

static int ebpf_test_sync(int selector)
{
    struct sync_bpf *obj = NULL;

    obj = sync_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");

        return 5;
    }

    if (!selector)
        selector++;

    int ret = ebpf_load_and_attach(obj, selector, NETDATA_SYNC_SYSCALL);
    if (!ret) {
        int fd = bpf_map__fd(obj->maps.tbl_sync) ;
        ret = sync_tests(fd);
    }

    sync_bpf__destroy(obj);

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
                          ebpf_print_help(argv[0], "sys_syncfs", 1);
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
        if (bf)
            selector = ebpf_find_functions(bf, selector, ebpf_sync_syscall, NETDATA_END_SYNC_ENUM);
    }

    ret = ebpf_fcnt_tests(syncfs, NETDATA_SYNCFS_SYSCALL, selector);
    if (!ret)
        ret = ebpf_msync_tests(selector);

    if (!ret)
        ret = ebpf_sync_file_range_tests(selector);

    if (!ret)
        ret = ebpf_fcnt_tests(fsync, NETDATA_FSYNC_SYSCALL, selector);

    if (!ret)
        ret = ebpf_fcnt_tests(fdatasync, NETDATA_FDATASYNC_SYSCALL, selector);

    if (!ret)
        ret = ebpf_test_sync(selector);

    if (bf)
        btf__free(bf);

    unlink(filename);

    return ret;
}

