#!/bin/sh

KERNEL_DIR="kernel/"

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Give major and minor version"
    exit 1
fi

VER_MAJOR="$1"
VER_MINOR="$2"

cp "${KERNEL_DIR}rcachestat_kern.o" "rnetdata_ebpf_cachestat.${VER_MAJOR}.${VER_MINOR}.o"
cp "${KERNEL_DIR}pcachestat_kern.o" "pnetdata_ebpf_cachestat.${VER_MAJOR}.${VER_MINOR}.o"
cp "${KERNEL_DIR}rmsync_kern.o" "rnetdata_ebpf_msync.${VER_MAJOR}.${VER_MINOR}.o"
cp "${KERNEL_DIR}pmsync_kern.o" "pnetdata_ebpf_msync.${VER_MAJOR}.${VER_MINOR}.o"
cp "${KERNEL_DIR}rnetwork_viewer_kern.o" "rnetdata_ebpf_socket.${VER_MAJOR}.${VER_MINOR}.o"
cp "${KERNEL_DIR}pnetwork_viewer_kern.o" "pnetdata_ebpf_socket.${VER_MAJOR}.${VER_MINOR}.o"
cp "${KERNEL_DIR}rprocess_kern.o" "rnetdata_ebpf_process.${VER_MAJOR}.${VER_MINOR}.o"
cp "${KERNEL_DIR}pprocess_kern.o" "pnetdata_ebpf_process.${VER_MAJOR}.${VER_MINOR}.o"
cp "${KERNEL_DIR}rsync_kern.o" "rnetdata_ebpf_sync.${VER_MAJOR}.${VER_MINOR}.o"
cp "${KERNEL_DIR}psync_kern.o" "pnetdata_ebpf_sync.${VER_MAJOR}.${VER_MINOR}.o"
cp "${KERNEL_DIR}rsyncfs_kern.o" "rnetdata_ebpf_syncfs.${VER_MAJOR}.${VER_MINOR}.o"
cp "${KERNEL_DIR}psyncfs_kern.o" "pnetdata_ebpf_syncfs.${VER_MAJOR}.${VER_MINOR}.o"
