#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>

#include <sys/mman.h>

#include "sync.skel.h"
#include "netdata_tests.h"

enum netdata_sync_enum {
    NETDATA_SYNCFS_SYSCALL,
    NETDATA_MSYNC_SYSCALL,

    NETDATA_END_SYNC_ENUM
};

static char *ebpf_sync_syscall[NETDATA_END_SYNC_ENUM] = {
    "__x64_sys_syncfs",
    "__x64_sys_msync"
};

void test_syncfs_synchronization()
{
    char *filename = { "useless_data.txt" };
    int fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0660);
    if (fd < 0 ) {
        perror("Cannot open file descriptor");
        return;
    }

    int i;
    for ( i = 0 ; i < 1000; i++ )
        write(fd, "synchronize the data after this.", 32);

    syncfs(fd);
    close(fd);

    sleep(2);

    unlink(filename);
}

int syncfs_tests(int fd) {
    test_syncfs_synchronization();

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

static inline int find_sync_id(struct btf *bf, char *name)
{
    const struct btf_type *type = netdata_find_bpf_attach_type(bf);
    if (!type)
        return -1;

    const struct btf_enum *e = btf_enum(type);
    int i, id;
    for (id = -1, i = 0; i < btf_vlen(type); i++, e++) {
        if (!strcmp(btf__name_by_offset(bf, e->name_off), "BPF_TRACE_FENTRY")) {
            id = btf__find_by_name_kind(bf, name, BTF_KIND_FUNC);
            break;
        }
    }

    return id;
}

static inline int ebpf_load_and_attach(struct sync_bpf *obj, int id, char *name)
{
    if (id > 0) {
        bpf_program__set_autoload(obj->progs.netdata_sync_kprobe, false);
        bpf_program__set_attach_target(obj->progs.netdata_sync_fentry, 0,
                                       name);
    } else {
        bpf_program__set_autoload(obj->progs.netdata_sync_fentry, false);
    }

    int ret = sync_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    }

    if (id > 0)
        ret = sync_bpf__attach(obj);
    else {
        obj->links.netdata_sync_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_sync_kprobe,
                                                                    false, name);
        ret = libbpf_get_error(obj->links.netdata_sync_kprobe);
    }

    if (!ret)
        fprintf(stdout, "%s: %s loaded with success\n", name, (id > 0) ? "entry" : "probe");

     return ret;
}

int ebpf_syncfs_tests(struct btf *bf, int id)
{
    struct sync_bpf *obj = NULL;

    obj = sync_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");
        if (bf)
            btf__free(bf);

        return 2;
    }

    int ret = ebpf_load_and_attach(obj, id, ebpf_sync_syscall[NETDATA_SYNCFS_SYSCALL]);
    if (!ret) {
        int fd = bpf_map__fd(obj->maps.tbl_sync) ;
        ret = syncfs_tests(fd);
    } else
        fprintf(stderr, "Error to attach BPF program\n");

    sync_bpf__destroy(obj);

    return 0;
}

// test based on IBM example https://www.ibm.com/support/knowledgecenter/en/ssw_ibm_i_71/apis/msync.htm
void test_msync_synchronization()
{
    int pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize < 0) {
        perror("Cannot get page size");
        return;
    }

    char *filename = { "useless_data.txt" };
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

    unlink(filename);
}

int msync_tests(int fd) {
    test_msync_synchronization();

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

int ebpf_msync_tests(struct btf *bf, int id)
{
    struct sync_bpf *obj = NULL;

    obj = sync_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");
        if (bf)
            btf__free(bf);

        return 2;
    }

    int ret = ebpf_load_and_attach(obj, id, ebpf_sync_syscall[NETDATA_MSYNC_SYSCALL]);
    if (!ret) {
        int fd = bpf_map__fd(obj->maps.tbl_sync) ;
        ret = msync_tests(fd);
    } else
        fprintf(stderr, "Error to attach BPF program\n");

    sync_bpf__destroy(obj);

    return 0;
}

int main(int argc, char **argv)
{
    static struct option long_options[] = {
        {"help",        no_argument,    0,  'h' },
        {"probe",       no_argument,    0,  'p' },
        {"trampoline",  no_argument,    0,  't' },
        {0, 0, 0, 0}
    };

    int selector = 0;
    int option_index = 0;
    while (1) {
        int c = getopt_long(argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h': {
                          ebpf_print_help(argv[0], "sys_syncfs");
                          exit(0);
                      }
            case 'p': {
                          selector = -1;
                          break;
                      }
            case 't': {
                          //id is already set to 0
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
    int id = -1;
    if (!selector) {
        if (bf) {
            id = find_sync_id(bf, ebpf_sync_syscall[NETDATA_SYNCFS_SYSCALL]);
        }

        bf = netdata_parse_btf_file((const char *)NETDATA_BTF_FILE);
    }

    ret = ebpf_syncfs_tests(bf, id);
    if (!ret)
        ret = ebpf_msync_tests(bf, id);

    if (bf)
        btf__free(bf);

    return ret;
}

