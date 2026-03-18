#define KBUILD_MODNAME "oomkill_netdata"
#include <linux/ptrace.h>
#include <linux/oom.h>
#include <linux/threads.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "netdata_ebpf.h"

NETDATA_BPF_HASH_DEF(tbl_oomkill, int, __u8, NETDATA_OOMKILL_MAX_ENTRIES);

SEC("tracepoint/oom/mark_victim")
int netdata_oom_mark_victim(struct netdata_oom_mark_victim_entry *ptr) {
    u8 zero = 0;
    int pid;
    bpf_probe_read(&pid, sizeof(pid), &ptr->pid);
    bpf_map_update_elem(&tbl_oomkill, &pid, &zero, BPF_ANY);
    return 0;
}

char _license[] SEC("license") = "GPL";
