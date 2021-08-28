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
    // there will likely never be many OOM kills to track simultaneously within
    // a very short period of time, so this number is plenty sufficient.
    .max_entries = 256
};

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0))
SEC("kprobe/oom_kill_process")
int netdata_oom_kill_process(
    struct pt_regs *ctx,
    struct task_struct *p,
    gfp_t gfp_mask,
    int order,
    unsigned int points,
    unsigned long totalpages,
    struct mem_cgroup *memcg,
    nodemask_t *nodemask,
    const char *message
) {
#else
SEC("kprobe/out_of_memory")
int netdata_out_of_memory(
    struct pt_regs *ctx,
    struct oom_control *oc
) {
    struct task_struct *p = oc->chosen;
#endif

    u32 key;
    netdata_oomkill_t val = {}, *valp;

    key = p->pid;
    valp = bpf_map_lookup_elem(&tbl_oomkill, &key);
    if (valp) {
        libnetdata_update_u32(&valp->killcnt, 1);
    } else {
        val.killcnt = 1;
        bpf_probe_read_kernel(&val.comm, sizeof(val.comm), p->comm);
        bpf_map_update_elem(&tbl_oomkill, &key, &val, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
