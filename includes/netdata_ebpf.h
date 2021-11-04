// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_EBPF_
#define _NETDATA_EBPF_ 1

/*
The main header.

This header has the common definitions for all `.c` files.
*/

#include <linux/sched.h>
#include <linux/version.h>
#include <linux/types.h>

#include "netdata_common.h"
#include "netdata_cache.h"
#include "netdata_dc.h"
#include "netdata_disk.h"
#include "netdata_fd.h"
#include "netdata_fs.h"
#include "netdata_hardirq.h"
#include "netdata_mdflush.h"
#include "netdata_mount.h"
#include "netdata_oomkill.h"
#include "netdata_process.h"
#include "netdata_shm.h"
#include "netdata_socket.h"
#include "netdata_softirq.h"
#include "netdata_sync.h"
#include "netdata_swap.h"
#include "netdata_vfs.h"

#endif /* _NETDATA_EBPF_ */

