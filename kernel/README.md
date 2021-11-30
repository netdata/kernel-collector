# eBPF Programs

All of the legacy (i.e. non-CO-RE) eBPF programs belong in this directory.

The following provides a short description for each of the `eBPF` programs we
have:

- `cachestat_kern.c`: provides Linux page cache monitoring.
- `dc_kern.c`: provides Linux directory cache monitoring.
- `disk_kern.c`: provides disk latency monitoring.
- `ext4_kern.c`: provides ext4 monitoring.
- `fdatasync_kern.c`: monitor calls for syscall `fdatasync`.
- `fsync_kern.c`: monitor calls for syscall `fsync`.
- `hardirq_kern.c`: provides hard interrupt (hard IRQ) latency monitoring.
- `mdflush_kern.c`: monitor flushes at the md driver level.
- `mount_kern.c`: monitor calls for syscalls `mount` and `umount`.
- `msync_kern.c`: monitor calls for syscall `msync`.
- `nfs_kern.c`: provides nfs monitoring.
- `oomkill_kern.c`: provides info on which processes got OOM killed.
- `process_kern.c`: provides process, file and VFS stats.
- `shm_kern.c`: monitor calls for syscalls `shmget`, `shmat`, `shmdt` and `shmctl`.
- `socket_kern.c`: provides network stats;
- `softirq_kern.c`: provides software interrupt (soft IRQ) latency monitoring.
- `swap_kern.c`: provides swap stats;
- `sync_file_range_kern.c`: monitor calls for syscall `sync_file_range`.
- `sync_kern.c`: monitor calls for syscall `sync`.
- `syncfs_kern.c`: monitor calls for syscall `syncfs`.
- `vfs_kern.c`: monitor Virtual Filesystem functions.
- `xfs_kern.c`: provides XFS monitoring.
- `zfs_kern.c`: provides ZFS monitoring.
