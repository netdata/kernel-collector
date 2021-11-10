#include <stdio.h>
#include <stdint.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "syncfs.skel.h"
#include "netdata_tests.h"

void test_synchronization()
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
    test_synchronization();

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

int main(int argc, char **argv)
{
    // Adjust memory
    int ret = netdata_ebf_memlock_limit();
    if (ret) {
        fprintf(stderr, "Cannot increase memory: error = %d\n", ret);
        return 1;
    }

    struct syncfs_bpf *obj = syncfs_bpf__open_and_load();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");
        return 2;
    }

    ret = syncfs_bpf__attach(obj);
    if (!ret) {
        int fd = bpf_map__fd(obj->maps.tbl_syncfs) ;
        ret = syncfs_tests(fd);
    } else
        fprintf(stderr, "Error to attach BPF program\n");

    syncfs_bpf__destroy(obj);

    return ret;
}
