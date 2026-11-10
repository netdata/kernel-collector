# Collector stream variants

## Approved scope and design

- Add buffer and arena event variants for the 15 legacy kprobe families without them: btrfs, disk, ext4, fdatasync, fsync, mdflush, mount, msync, network_viewer, nfs, sync, sync_file_range, syncfs, xfs, and zfs.
- Keep hardirq and softirq outside this change because they use tracepoints.
- Emit domain-specific records at the point where each collector has the result: operation and latency for filesystems, device and latency for disk, array unit for mdflush, syscall outcome for mount, socket key and data for network_viewer, and call records for sync syscalls.
- Preserve existing aggregate maps and their behavior. A full event queue may drop an event without changing aggregate accounting.
- Enable and test both flavors in the build and both repository testers.

## Review decisions

1. Event emission is not gated by `monitor_apps()`: buffer and arena objects are loaded only when the agent consumes the event stream, and a full queue counts drops.
2. `pid` and `tgid` follow the controller apps level where a controller table exists; other collectors report the current thread and process.
3. `disk.device` uses the `tbl_disk_iocall` encoding so one decoder serves both.
4. Live verifier loading is run by the user with elevated privileges.

## Implementation risks and checks

- Return probes and entry probes have different available context. Emit completed-operation records only after the existing collector has calculated the result.
- Network Viewer updates existing socket records in place; emit after both updates and new map insertions.
- The arena queue must fit in its map, and event slots must be published only after the payload is initialized.
- Verify both BPF object flavors compile on a configured kernel and that the testers discover their names and consume their event maps.

## Event ABI

Each new object exposes `collector_events`. Buffer objects use a ring buffer; arena objects use the same bounded slot queue as the existing arena collectors. Both transport modes carry `struct netdata_stream_event_t` from `includes/netdata_stream.h`.

The common fields are `timestamp_ns`, `pid`, `tgid`, and `action`. The object name identifies the collector.

- Collectors with a controller table (`btrfs`, `disk`, `ext4`, `network_viewer`, `nfs`, `xfs`, `zfs`) fill `pid` and `tgid` with `netdata_get_pid()`, so `pid` follows the apps level selected by the agent, as in the existing buffer collectors. With the ignore level, both are zero.
- Collectors without a controller table (`fdatasync`, `fsync`, `mdflush`, `mount`, `msync`, `sync`, `sync_file_range`, `syncfs`) report the current thread ID in `pid` and the current process ID in `tgid`.
- Disk completion can run in interrupt context, so its `pid` and `tgid` identify whichever task was current, not the task that issued the request.

The `details` union is interpreted by collector:

- Filesystem collectors (`btrfs`, `ext4`, `nfs`, `xfs`, `zfs`): `fs.latency_us`; `action` is the existing read, write, open, or sync selector.
- `disk`: `disk.device` is the device number in the same encoding as the `tbl_disk_iocall` key (`netdata_new_encode_dev()`), `disk.sector` is the request sector, and `disk.latency_us` is completion latency.
- `mdflush`: `md.unit` is the normalized md unit number.
- `mount`: `mount.result` is the syscall return value when `mount.result_known` is one. Entry-probe objects set `result_known` to zero.
- `network_viewer`: `network.key` and `network.data` are snapshots of the existing socket map key and value after the operation; `action` identifies which operation updated them.
- Sync syscall collectors (`fdatasync`, `fsync`, `msync`, `sync`, `sync_file_range`, `syncfs`): `action` is `NETDATA_STREAM_CALL`.

Unselected union bytes are zero. Buffer and arena event records have the same layout. The arena queue has 1024 slots and uses `head`, `tail`, `ready`, and `dropped` as defined in `netdata_arena_common.h`. The tester drain routine advances `tail` and clears `ready` after reading each published slot.

## Verification

- Built entry and return objects for all 15 base collectors and all 15 buffer and arena variants against the configured 7.2 kernel headers. Each of the 60 new flavor artifacts has an event map and license; arena artifacts also have arena state.
- The Go tester suite passes, the C tester compiles, and a local queue-drain check passes.
- Live loading remains unverified in this environment because the tester cannot raise its memory limit, including during an elevated retry.
