# Kernel code

Inside this directory we have the `eBPF` programs source code. Until gcc 10.0
is released, which will be able to compile these files, it will be necessary to
use at least the `clang 4.0` and `llvm 4.0`.

## Files

### Makefile

The Makefile uses some commands to define variables, but there is a
peculiarity. You need to change the `KERNELSOURCE` variable manually depending
of your distribution.

### Source Code

Right now we have the following `eBPF` program collectors:

- `cachestat_kern.c`      : provides Linux page cache monitoring.
- `dc_kern.c`             : provides Linux directory cache monitoring.
- `disk_kern.c`           : provides disk latency monitoring.
- `ext4_kern.c`           : provides ext4 monitoring.
- `fdatasync_kern.c`      : monitor calls for syscall `fdatasync`.
- `fsync_kern.c`          : monitor calls for syscall `fsync`.
- `hardirq_kern.c`        : provides hard interrupt (hard IRQ) latency monitoring.
- `mount_kern.c`          : monitor calls for syscalls `mount` and `umount`.
- `msync_kern.c`          : monitor calls for syscall `msync`.
- `nfs_kern.c`            : provides nfs monitoring.
- `oomkill_kern.c`        : provides info on which processes got OOM killed.
- `process_kern.c`        : provides process, file and VFS stats.
- `socket_kern.c`         : provides network stats;
- `softirq_kern.c`        : provides software interrupt (soft IRQ) latency monitoring.
- `swap_kern.c`           : provides swap stats;
- `sync_file_range_kern.c`: monitor calls for syscall `sync_file_range`.
- `sync_kern.c`           : monitor calls for syscall `sync`.
- `syncfs_kern.c`         : monitor calls for syscall `syncfs`.
- `vfs_kern.c`            : monitor Virtual Filesystem functions.
- `xfs_kern.c`            : provides XFS monitoring.
- `zfs_kern.c`            : provides ZFS monitoring.
