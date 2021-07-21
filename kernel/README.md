# Kernel code

Inside this directory we have the `eBPF programs` source code. Until gcc 10.0 to be released to compile
these files it will be necessary to use at least the `clang 4.0` and `llvm 4.0`.

## Files

### Makefile

The Makefile uses some commands to define variables, but there is a peculiarity. You need to change
the `KERNEL_SOURCE` variable manually depending of your distribution.

### Headers

This directory has two headers:

-  `netdata_asm_goto.h`: This is the header that allows to compile our code on RH 7.x family.
-  `netdata_ebpf.h`: The main header, this header has the common definitions for all `.c` files. 

### Source Code

Right now we have two `eBPF` program collections:

-  `cachestat_kern.c`      : eBPF program that provides Linux page cache monitoring.
-  `dc_kern.c`             : eBPF program that provides Linux directory cache monitoring.
-  `disk_kern.c`           : eBPF program that provides disk latency monitoring.
-  `ext4_kern.c`           : eBPF program that provides ext4 monitoring.
-  `fdatasync_kern.c`      : eBPF program that monitor calls for syscall `fdatasync`.
-  `fsync_kern.c`          : eBPF program that monitor calls for syscall `fsync`.
-  `mount_kern.c`          : eBPF program that monitor calls for syscalls `mount` and `umount`.
-  `msync_kern.c`          : eBPF program that monitor calls for syscall `msync`.
-  `nfs_kern.c`            : eBPF program that provides nfs monitoring.
-  `process_kern.c`        : eBPF program that provides process, file and VFS stats.
-  `socket_kern.c`         : eBPF program that provides network stats;
-  `swap_kern.c`           : eBPF program that provides swap stats;
-  `sync_file_range_kern.c`: eBPF program that monitor calls for syscall `sync_file_range`.
-  `sync_kern.c`           : eBPF program that monitor calls for syscall `sync`.
-  `syncfs_kern.c`         : eBPF program that monitor calls for syscall `syncfs`.
-  `vfs_kern.c`            : eBPF program that monitor Virtual Filesystem functions.
-  `xfs_kern.c`            : eBPF program that provides XFS monitoring.
-  `zfs_kern.c`            : eBPF program that provides ZFS monitoring.

