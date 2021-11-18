#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/mount.h>

#include "netdata_tests.h"
#include "netdata_mount.h"

#include "mount.skel.h"

int main(int argc, char **argv)
{
    static struct option long_options[] = {
        {"help",        no_argument,    0,  'h' },
        {"probe",       no_argument,    0,  'p' },
        {"tracepoint",  no_argument,    0,  't' },
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
                          ebpf_print_help(argv[0], "mount", 0);
                          exit(0);
                      }
            case 'p': {
                          selector = 0;
                          break;
                      }
            case 'r': {
                          selector = 1;
                          break;
                      }
            default: {
                         break;
                     }
        }
    }

    return 0;
}
