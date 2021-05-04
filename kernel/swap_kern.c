#define KBUILD_MODNAME "swap_netdata"
#include <linux/bpf.h>
#include <linux/ptrace.h>

#include <linux/threads.h>

#include "bpf_helpers.h"
#include "netdata_ebpf.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

struct bpf_map_def SEC("maps") tbl_swap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_SWAP_END
};

struct bpf_map_def SEC("maps") tbl_pid_swap = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)) 
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u32),
    .value_size = sizeof(netdata_swap_access_t),
    .max_entries = PID_MAX_DEFAULT
};

/************************************************************************************
 *
 *                               SYNC SECTION
 *
 ***********************************************************************************/

SEC("kprobe/swap_readpage")
int netdata_swap_readpage(struct pt_regs* ctx)
{
    netdata_swap_access_t data = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    libnetdata_update_global(&tbl_swap, NETDATA_KEY_SWAP_READPAGE_CALL, 1);

    netdata_swap_access_t *fill = bpf_map_lookup_elem(&tbl_pid_swap ,&pid);
    if (fill) {
        libnetdata_update_u64(&fill->read, 1);
    } else {
        data.read = 1;
        bpf_map_update_elem(&tbl_pid_swap, &pid, &data, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/swap_writepage")
int netdata_swap_writepage(struct pt_regs* ctx)
{
    netdata_swap_access_t data = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    libnetdata_update_global(&tbl_swap, NETDATA_KEY_SWAP_WRITEPAGE_CALL, 1);

    netdata_swap_access_t *fill = bpf_map_lookup_elem(&tbl_pid_swap ,&pid);
    if (fill) {
        libnetdata_update_u64(&fill->write, 1);
    } else {
        data.write = 1;
        bpf_map_update_elem(&tbl_pid_swap, &pid, &data, BPF_ANY);
    }

    return 0;
}

/************************************************************************************
 *
 *                             END SYNC SECTION
 *
 ***********************************************************************************/

char _license[] SEC("license") = "GPL";

