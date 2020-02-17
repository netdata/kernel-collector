#!/bin/bash

set -e

build() {
  echo "[XXX]: Building against Kernel ${KERNEL_VERSION} for libc ${_LIBC} ..."
  (
    cd user || exit 1
    make CFLAGS='-fno-stack-protector -I /usr/src/linux/usr/include'
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
