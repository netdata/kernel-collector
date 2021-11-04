// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_COMMON_
#define _NETDATA_COMMON_ 1

struct netdata_error_report_t {
    char comm[TASK_COMM_LEN];
    __u32 pid;

    int type;
    int err;
};

enum netdata_controller {
    NETDATA_CONTROLLER_APPS_ENABLED,

    NETDATA_CONTROLLER_END
};

// Use __always_inline instead inline to keep compatiblity with old kernels
// https://docs.cilium.io/en/v1.8/bpf/
// The condition to test kernel was added, because __always_inline broke the epbf.plugin
// on CentOS 7 and Ubuntu 18.04 (kernel 4.18)
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,19,0)) 
static __always_inline void libnetdata_update_u64(__u64 *res, __u64 value)
#else
static inline void libnetdata_update_u64(__u64 *res, __u64 value)
#endif
{
    __sync_fetch_and_add(res, value);
    if ( (0xFFFFFFFFFFFFFFFF - *res) <= value) {
        *res = value;
    }
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,19,0)) 
static __always_inline void libnetdata_update_global(void *tbl,__u32 key, __u64 value)
#else
static inline void libnetdata_update_global(void *tbl,__u32 key, __u64 value)
#endif
{
    __u64 *res;
    res = bpf_map_lookup_elem(tbl, &key);
    if (res)
        libnetdata_update_u64(res, value) ;
    else
        bpf_map_update_elem(tbl, &key, &value, BPF_NOEXIST);
}

/**
 * The motive we are using log2 to plot instead the raw value is well explained
 * inside this paper https://www.fsl.cs.stonybrook.edu/docs/osprof-osdi2006/osprof.pdf
 */
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,19,0))
static __always_inline unsigned int libnetdata_log2(unsigned int v)
#else
static inline unsigned int libnetdata_log2(unsigned int v)
#endif
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

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,19,0))
static __always_inline unsigned int libnetdata_log2l(__u64 v)
#else
static inline unsigned int libnetdata_log2l(__u64 v)
#endif
{
    unsigned int hi = v >> 32;
    if (hi)
        return libnetdata_log2(hi) + 32;
    else
        return libnetdata_log2(v);
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,19,0))
static __always_inline void libnetdata_update_u32(u32 *res, u32 value) 
#else
static inline void libnetdata_update_u32(u32 *res, u32 value) 
#endif
{
    if (!value)
        return;

    __sync_fetch_and_add(res, value);
    if ( (0xFFFFFFFF - *res) <= value) {
        *res = value;
    }
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,19,0))
static __always_inline __u32 libnetdata_select_idx(__u64 val, __u32 end)
#else
static inline __u32 libnetdata_select_idx(__u64 val, __u32 end)
#endif
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

#endif /* _NETDATA_COMMON_ */

