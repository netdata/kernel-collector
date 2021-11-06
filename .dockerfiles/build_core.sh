#!/bin/bash

set -e

build() {
  echo "[XXX]: Building against Kernel 5.15 for libc ${_LIBC} ..."
  (
    cd co-re
    make
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
