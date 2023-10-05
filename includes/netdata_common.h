// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_COMMON_
#define _NETDATA_COMMON_ 1

#include "netdata_defs.h"

struct netdata_error_report_t {
    char comm[TASK_COMM_LEN];
    __u32 pid;

    int type;
    int err;
};

static __always_inline void libnetdata_update_u64(__u64 *res, __u64 value)
{
    __sync_fetch_and_add(res, value);
    if ( (0xFFFFFFFFFFFFFFFF - *res) <= value) {
        *res = value;
    }
}

static __always_inline void libnetdata_update_s64(__u64 *res, __s64 value)
{
    __sync_fetch_and_add(res, value);
}

static __always_inline void libnetdata_update_global(void *tbl, __u32 key, __u64 value)
{
    __u64 *res;
    res = bpf_map_lookup_elem(tbl, &key);
    if (res)
        libnetdata_update_u64(res, value) ;
    else
        bpf_map_update_elem(tbl, &key, &value, BPF_EXIST);
}

static __always_inline void libnetdata_update_sglobal(void *tbl, __u32 key, __s64 value)
{
    __s64 *res;
    res = bpf_map_lookup_elem(tbl, &key);
    if (res)
        libnetdata_update_s64(res, value) ;
    else
        bpf_map_update_elem(tbl, &key, &value, BPF_EXIST);
}

/**
 * The motive we are using log2 to plot instead the raw value is well explained
 * inside this paper https://www.fsl.cs.stonybrook.edu/docs/osprof-osdi2006/osprof.pdf
 */
static __always_inline unsigned int libnetdata_log2(unsigned int v)
{
    unsigned int r;
    unsigned int shift;

    r = (v > 0xFFFF) << 4; v >>= r;
    shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
    shift = (v > 0xF) << 2; v >>= shift; r |= shift;
    shift = (v > 0x3) << 1; v >>= shift; r |= shift;
    r |= (v >> 1);

    return r;
}

static __always_inline unsigned int libnetdata_log2l(__u64 v)
{
    unsigned int hi = v >> 32;
    if (hi)
        return libnetdata_log2(hi) + 32;
    else
        return libnetdata_log2(v);
}

static __always_inline void libnetdata_update_u32(u32 *res, u32 value) 
{
    if (!value)
        return;

    __sync_fetch_and_add(res, value);
    if ( (0xFFFFFFFF - *res) <= value) {
        *res = value;
    }
}

static __always_inline __u32 libnetdata_select_idx(__u64 val, __u32 end)
{
    __u32 rlog;

    rlog = libnetdata_log2l(val);

    if (rlog > end)
        rlog = end;

    return rlog;
}

// Copied from linux/samples/bpf/tracex1_kern.c
#define _(P)                                                                   \
        ({                                                                     \
                typeof(P) val = 0;                                             \
                bpf_probe_read(&val, sizeof(val), &(P));                       \
                val;                                                           \
        })

// Copied from linux/samples/bpf/trace_common.h
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))

#ifdef __x86_64__
#define NETDATA_SYSCALL(SYS) "__x64_sys_" __stringify(SYS)
#elif defined(__s390x__)
#define NETDATA_SYSCALL(SYS) "__s390x_" __stringify(SYS)
#else
#define NETDATA_SYSCALL(SYS) "sys_" __stringify(SYS)
#endif

#else
#define NETDATA_SYSCALL(SYS) "sys_" __stringify(SYS)
#endif

/*
the TP_DATA_LOC_READ_* macros are used for reading from a field that's pointed
to by a __data_loc variable.

FYI, a __data_loc variable is really an int that contains within it the data
needed to get the location of the actual value. these macros do the
transformation needed to get that final location and then read from it.

this code is from iovisor/bcc file src/cc/exports/helpers.h and modified by
Netdata's Agent team for inclusion in Netdata.
*/
#define TP_DATA_LOC_READ_CONST(_dst, _arg, _data_loc, _length) do {           \
    unsigned short __offset = _data_loc & 0xFFFF;                             \
    bpf_probe_read((void *)_dst, _length, (char *)_arg + __offset);           \
} while (0)
#define TP_DATA_LOC_READ(_dst, _arg, _data_loc) do {                          \
    unsigned short __offset = _data_loc & 0xFFFF;                             \
    unsigned short __length = _data_loc >> 16;                                \
    bpf_probe_read((void *)_dst, __length, (char *)_arg + __offset);          \
} while (0)

// Get real parent PID
static __always_inline __u32 netdata_get_real_parent_pid()
{
    __u32 ppid;
    struct task_struct *task, *real_parent;

    task = (struct task_struct *)bpf_get_current_task();
    real_parent = _(task->real_parent);
    bpf_probe_read(&ppid, sizeof(__u32), &real_parent->tgid);

    return ppid;
}

static __always_inline __u32 netdata_get_parent_pid()
{
    __u32 ppid;
    struct task_struct *task, *parent;

    task = (struct task_struct *)bpf_get_current_task();
    parent = _(task->parent);
    bpf_probe_read(&ppid, sizeof(__u32), &parent->tgid);

    return ppid;
}

static __always_inline __u32 netdata_get_current_pid(__u32 *tgid)
{
    __u32 pid;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    pid = (__u32)pid_tgid;
    *tgid = (__u32)(pid_tgid>>32);

    return pid;
}

static __always_inline __u32 netdata_get_pid(void *ctrl_tbl, __u32 *tgid)
{
    __u32 key = NETDATA_CONTROLLER_APPS_LEVEL;

    __u64 *level = bpf_map_lookup_elem(ctrl_tbl ,&key);
    if (level) {
        if (*level == NETDATA_APPS_LEVEL_REAL_PARENT) {
            __u64 pid_tgid = bpf_get_current_pid_tgid();
            *tgid = (__u32)(pid_tgid>>32);
            return netdata_get_real_parent_pid();
        } else if (*level == NETDATA_APPS_LEVEL_PARENT) {
            __u64 pid_tgid = bpf_get_current_pid_tgid();
            *tgid = (__u32)(pid_tgid>>32);
            return netdata_get_parent_pid();
        } else if (*level == NETDATA_APPS_LEVEL_ALL)
            return netdata_get_current_pid(tgid);
        else if (*level == NETDATA_APPS_LEVEL_IGNORE) // Ignore PID
            return 0;
    }

    return netdata_get_real_parent_pid();
}

static __always_inline void *netdata_get_pid_structure(__u32 *store_pid, __u32 *store_tgid, void *ctrl_tbl, void *pid_tbl)
{
    __u32 pid =  netdata_get_pid(ctrl_tbl, store_tgid);

    *store_pid = pid;

    return bpf_map_lookup_elem(pid_tbl, store_pid);
}

static __always_inline __u32 monitor_apps(void *ctrl_tbl)
{
    __u32 apps_key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u64 *apps = bpf_map_lookup_elem(ctrl_tbl ,&apps_key);
    if (!apps || (apps && *apps == 0))
        return 0;

    return 1;
}

#endif /* _NETDATA_COMMON_ */

