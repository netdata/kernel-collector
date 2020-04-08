# Netdata Shared Library

This directory is used to make Netdata shared library used to load the `eBPF` programs. The file
`api.c` is used to map some functions from `libbpf`, in normal situation we do not call these functions.

The files `bpf_load.c` and `trace_helpers.c` are also files from kernel source, but we need to add some
`#ifdef`s to it to compile on all kernels that we support.
