#!/bin/bash

set -e

build() {
  echo "[XXX]: Preparing kernel headers for ${KERNEL_VERSION}..."
  (
    if [ "${KERNEL_VERSION}" !=  "3.10.0-1160.108.1.el7" ]; then
       make defconfig -C /usr/src/linux
    else
       make silentoldconfig -C /usr/src/linux
    fi   
    make scripts -C /usr/src/linux
    make prepare -C /usr/src/linux
    make headers_install -C /usr/src/linux
  ) || return 1
  echo "[XXX]: Building against Kernel ${KERNEL_VERSION} for libc ${_LIBC} ..."
  (
    if [ "${DEBUG:-0}" -eq 1 ]; then
      echo "[XXX]: Building with debug symbols ..."
      make CFLAGS='-fno-stack-protector -I /usr/src/linux/usr/include' EXTRA_CFLAGS='-g -fno-stack-protector'
    else
      make CFLAGS='-fno-stack-protector -I /usr/src/linux/usr/include'
    fi
  ) || return 1
}

_main() {
  if ! build; then
    echo "ERROR: Build failed ..."
    if [ -t 1 ]; then
      echo "Dropping into a shell ..."
      exec /bin/sh
    else
      exit 1
    fi
  fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  _main "$@"
fi
