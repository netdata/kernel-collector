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
#include "netdata_socket.h"

#include "socket.skel.h"

char *function_list[] = { "inet_csk_accept",
                          "tcp_retransmit_skb",
                          "tcp_cleanup_rbuf",
                          "tcp_close",
                          "udp_recvmsg",
                          "tcp_sendmsg",
                          "udp_sendmsg" };

#define NETDATA_IPV4 4
#define NETDATA_IPV6 6

static int ebpf_attach_probes(struct socket_bpf *obj)
{
    obj->links.netdata_inet_csk_accept_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_inet_csk_accept_kretprobe,
                                                                              true, function_list[NETDATA_FCNT_INET_CSK_ACCEPT]);
    int ret = libbpf_get_error(obj->links.netdata_inet_csk_accept_kretprobe);
    if (ret)
        return -1;

    obj->links.netdata_tcp_retransmit_skb_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_tcp_retransmit_skb_kprobe,
                                                                              false, function_list[NETDATA_FCNT_TCP_RETRANSMIT]);
    ret = libbpf_get_error(obj->links.netdata_tcp_retransmit_skb_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_tcp_cleanup_rbuf_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_tcp_cleanup_rbuf_kprobe,
                                                                            false, function_list[NETDATA_FCNT_CLEANUP_RBUF]);
    ret = libbpf_get_error(obj->links.netdata_tcp_cleanup_rbuf_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_tcp_close_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_tcp_close_kprobe,
                                                                     false, function_list[NETDATA_FCNT_TCP_CLOSE]);
    ret = libbpf_get_error(obj->links.netdata_tcp_close_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_udp_recvmsg_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_udp_recvmsg_kprobe,
                                                                       false, function_list[NETDATA_FCNT_UDP_RECEVMSG]);
    ret = libbpf_get_error(obj->links.netdata_udp_recvmsg_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_udp_recvmsg_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_udp_recvmsg_kretprobe,
                                                                          true, function_list[NETDATA_FCNT_UDP_RECEVMSG]);
    ret = libbpf_get_error(obj->links.netdata_udp_recvmsg_kretprobe);
    if (ret)
        return -1;

    obj->links.netdata_tcp_sendmsg_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_tcp_sendmsg_kprobe,
                                                                       false, function_list[NETDATA_FCNT_TCP_SENDMSG]);
    ret = libbpf_get_error(obj->links.netdata_tcp_sendmsg_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_tcp_sendmsg_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_tcp_sendmsg_kretprobe,
                                                                          true, function_list[NETDATA_FCNT_TCP_SENDMSG]);
    ret = libbpf_get_error(obj->links.netdata_tcp_sendmsg_kretprobe);
    if (ret)
        return -1;

    obj->links.netdata_udp_sendmsg_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_udp_sendmsg_kprobe,
                                                                       false, function_list[NETDATA_FCNT_UDP_SENDMSG]);
    ret = libbpf_get_error(obj->links.netdata_udp_sendmsg_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_udp_sendmsg_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_udp_sendmsg_kretprobe,
                                                                          true, function_list[NETDATA_FCNT_UDP_SENDMSG]);
    ret = libbpf_get_error(obj->links.netdata_udp_sendmsg_kretprobe);
    if (ret)
        return -1;

    return 0;
}

static void ebpf_disable_probes(struct socket_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_inet_csk_accept_kretprobe, false);
}

static void ebpf_disable_trampoline(struct socket_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_inet_csk_accept_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_retransmit_skb_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_cleanup_rbuf_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_close_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_udp_recvmsg_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_sendmsg_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_sendmsg_fexit, false);
    bpf_program__set_autoload(obj->progs.netdata_udp_sendmsg_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_udp_sendmsg_fexit, false);
}

static void ebpf_set_trampoline_target(struct socket_bpf *obj)
{
    bpf_program__set_attach_target(obj->progs.netdata_inet_csk_accept_fentry, 0,
                                   function_list[NETDATA_FCNT_INET_CSK_ACCEPT]);

    bpf_program__set_attach_target(obj->progs.netdata_tcp_retransmit_skb_fentry, 0,
                                   function_list[NETDATA_FCNT_TCP_RETRANSMIT]);

    bpf_program__set_attach_target(obj->progs.netdata_tcp_cleanup_rbuf_fentry, 0,
                                   function_list[NETDATA_FCNT_CLEANUP_RBUF]);

    bpf_program__set_attach_target(obj->progs.netdata_tcp_close_fentry, 0,
                                   function_list[NETDATA_FCNT_TCP_CLOSE]);

    bpf_program__set_attach_target(obj->progs.netdata_udp_recvmsg_fentry, 0,
                                   function_list[NETDATA_FCNT_UDP_RECEVMSG]);

    bpf_program__set_attach_target(obj->progs.netdata_tcp_sendmsg_fentry, 0,
                                   function_list[NETDATA_FCNT_TCP_SENDMSG]);

    bpf_program__set_attach_target(obj->progs.netdata_tcp_sendmsg_fexit, 0,
                                   function_list[NETDATA_FCNT_TCP_SENDMSG]);

    bpf_program__set_attach_target(obj->progs.netdata_udp_sendmsg_fentry, 0,
                                   function_list[NETDATA_FCNT_UDP_SENDMSG]);

    bpf_program__set_attach_target(obj->progs.netdata_udp_sendmsg_fexit, 0,
                                   function_list[NETDATA_FCNT_UDP_SENDMSG]);
}


static inline int ebpf_load_and_attach(struct socket_bpf *obj, int selector)
{
    // Adjust memory
    int ret;
    if (!selector) { // trampoline
        ebpf_disable_probes(obj);

        ebpf_set_trampoline_target(obj);
    } else if (selector == NETDATA_MODE_PROBE) {  // kprobe
        ebpf_disable_trampoline(obj);
    }

    ret = socket_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    } 

    if (!selector) {
        ret = socket_bpf__attach(obj);
    } else {
        ret = ebpf_attach_probes(obj);
    }
    
    if (!ret) {
        fprintf(stdout, "Socket loaded with success\n");
    }

    return ret;
}

static inline pid_t update_global(struct socket_bpf *obj)
{
    int fd = bpf_map__fd(obj->maps.tbl_global_sock);
    return ebpf_fill_global(fd);
}

static inline int netdata_update_bandwidth(pid_t my_pid, struct socket_bpf *obj)
{
    netdata_bandwidth_t bandwidth = { .pid = (__u32) my_pid, .first = 123456789, .ct = 123456790,
                                      .bytes_sent = 1, .bytes_received = 1, .call_tcp_sent = 1,
                                      .call_tcp_received = 1, .retransmit = 1, .call_udp_sent = 1,
                                      .call_udp_received = 1 };
    uint32_t idx = (uint32_t)my_pid;
    int apps = bpf_map__fd(obj->maps.tbl_bandwidth);
    int ret = bpf_map_update_elem(apps, &idx, &bandwidth, 0);
    if (ret)
        fprintf(stderr, "Cannot insert value to bandwidth table.\n");

    return ret;
}

static inline int update_socket_tables(int fd, netdata_socket_idx_t *idx, netdata_socket_t *values)
{
    int ret = bpf_map_update_elem(fd, idx, values, 0);
    if (ret)
        fprintf(stderr, "Cannot insert value to socket table.\n");

    return ret;
}

static inline int update_local_ports(struct socket_bpf *obj)
{
    uint16_t idx = 1;
    uint8_t value = 1;
    int fd = bpf_map__fd(obj->maps.tbl_lports);
    int ret = bpf_map_update_elem(fd, &idx, &value, 0);
    if (ret)
        fprintf(stderr, "Cannot insert value to local port table.\n");

    return ret;
}

pid_t ebpf_update_tables(struct socket_bpf *obj, netdata_socket_idx_t *idx, netdata_socket_t *values)
{
    pid_t my_pid = update_global(obj);

    int has_error = netdata_update_bandwidth(my_pid, obj);

    int fd = bpf_map__fd(obj->maps.tbl_conn_ipv4);
    has_error += update_socket_tables(fd, idx, values);

    fd = bpf_map__fd(obj->maps.tbl_conn_ipv6);
    has_error += update_socket_tables(fd, idx, values);

    has_error += update_local_ports(obj);

    if (!has_error)
        fprintf(stdout, "Tables updated with success!\n");

    return my_pid;
}

static int netdata_read_bandwidth(pid_t pid, struct socket_bpf *obj, int ebpf_nprocs)
{
    netdata_bandwidth_t *stored = calloc((size_t)ebpf_nprocs, sizeof(netdata_bandwidth_t));
    if (!stored)
        return 2;

    uint64_t counter = 0;
    uint32_t idx = (uint32_t)pid;
    int apps = bpf_map__fd(obj->maps.tbl_bandwidth);
    if (!bpf_map_lookup_elem(apps, &idx, stored)) {
        int j;
        for (j = 0; j < ebpf_nprocs; j++) {
            counter += (stored[j].first + stored[j].ct + stored[j].bytes_sent + stored[j].bytes_received + 
                        stored[j].call_tcp_sent + stored[j].call_tcp_received + stored[j].retransmit +
                        stored[j].call_udp_sent + stored[j].call_udp_received);
        }
    }

    free(stored);

    if (counter) {
        return 0;
    }

    fprintf(stdout, "Cannot read apps data.\n");

    return 2;
}

static int netdata_read_socket(netdata_socket_idx_t *idx, struct socket_bpf *obj, int ebpf_nprocs, int ip_version)
{
    netdata_socket_t *stored = calloc((size_t)ebpf_nprocs, sizeof(netdata_socket_t));
    if (!stored)
        return 2;

    uint64_t counter = 0;
    int ip_fd = bpf_map__fd((ip_version == 4) ? obj->maps.tbl_conn_ipv4 : obj->maps.tbl_conn_ipv6);
    if (!bpf_map_lookup_elem(ip_fd, idx, stored)) {
        int j;
        for (j = 0; j < ebpf_nprocs; j++) {
            counter += (stored[j].recv_packets + stored[j].sent_packets + stored[j].recv_bytes + stored[j].sent_bytes +
                        stored[j].first + stored[j].ct + stored[j].retransmit);
        }
    }

    free(stored);

    if (counter) {
        return 0;
    }

    fprintf(stdout, "Cannot read IP%d socket data.\n", ip_version);

    return 2;
}

static int netdata_read_local_ports(struct socket_bpf *obj)
{
    uint16_t idx = 1;
    uint8_t value = 0;
    int fd = bpf_map__fd(obj->maps.tbl_lports);
    if (!bpf_map_lookup_elem(fd, &idx, &value)) {
        if (value)
            return 0;
    }

    fprintf(stdout, "Cannot read local ports data.\n");

    return 2;
}

int ebpf_socket_tests(int selector)
{
    struct socket_bpf *obj = NULL;
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);

    obj = socket_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");

        return 2;
    }

    int ret = ebpf_load_and_attach(obj, selector);
    if (!ret) {
        int fd = bpf_map__fd(obj->maps.socket_ctrl);
        update_controller_table(fd);

        netdata_socket_idx_t common_idx = { .saddr.addr64 = { 1, 1 }, .sport = 1, .daddr.addr64 = {1 , 1}, .dport = 1 };
        netdata_socket_t values = { .recv_packets = 1, .sent_packets = 1, .recv_bytes = 1, .sent_bytes = 1,
                                    .first = 123456789, .ct = 123456790, .retransmit = 1, .protocol = 6,
                                    .reserved = 1 }; 
        pid_t my_pid = ebpf_update_tables(obj, &common_idx, &values);

        // Separator between load and result
        fprintf(stderr, "\n=================  READ DATA =================\n\n");
        ret =  ebpf_read_global_array(fd, ebpf_nprocs, NETDATA_SOCKET_COUNTER);
        if (!ret) {

            ret += netdata_read_bandwidth(my_pid, obj, ebpf_nprocs);

            ret += netdata_read_socket(&common_idx, obj, ebpf_nprocs, NETDATA_IPV4);
            ret += netdata_read_socket(&common_idx, obj, ebpf_nprocs, NETDATA_IPV6);

            ret += netdata_read_local_ports(obj);

            if (!ret)
                fprintf(stderr, "All stored data were retrieved with success!\n");
        } else
            fprintf(stderr, "Cannot read global table\n");
    } else
        fprintf(stderr ,"%s", NETDATA_CORE_DEFAULT_ERROR);

    socket_bpf__destroy(obj);

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
                          ebpf_print_help(argv[0], "socket", 1);
                          exit(0);
                      }
            case 'p': {
                          selector = NETDATA_MODE_PROBE;
                          break;
                      }
            case 'r': {
                          selector = NETDATA_MODE_PROBE;
                          fprintf(stdout, "This specific software does not have tracepoint, using kprobe instead\n");
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

    return ebpf_socket_tests(selector);
}

