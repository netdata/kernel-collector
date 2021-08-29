#define KBUILD_MODNAME "oomkill_netdata"
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/oom.h>
#include <linux/threads.h>

#include "bpf_helpers.h"
#include "netdata_ebpf.h"

struct bpf_map_def SEC("maps") tbl_oomkill = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u32),
    .value_size = sizeof(netdata_oomkill_t),
    .max_entries = NETDATA_OOMKILL_MAX_ENTRIES
};

SEC("kprobe/mark_oom_victim")
int netdata_mark_oom_victim(struct pt_regs *ctx) {
    u32 key;
    netdata_oomkill_t val = {}, *valp;

    struct task_struct *p = (struct task_struct *)PT_REGS_PARM1(ctx);
    bpf_probe_read(&key, sizeof(key), &p->pid);
    valp = bpf_map_lookup_elem(&tbl_oomkill, &key);
    if (valp) {
        libnetdata_update_u32(&valp->killcnt, 1);
    } else {
        val.killcnt = 1;
        bpf_probe_read(val.comm, sizeof(val.comm), p->comm);
        bpf_map_update_elem(&tbl_oomkill, &key, &val, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
