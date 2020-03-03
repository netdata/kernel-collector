#!/bin/sh

log() {
  printf "%s\n" "${1}"
}

error() {
  log "ERROR: ${1}"
}

fail() {
  log "FATAL: ${1}"
  exit 1
}

if [ "$#" -eq 0 ]; then
  log "Usage: $(basename "$0") <kernel_version> [<libc>]"
  exit 1
fi

KERNEL_VERSION="${1}"
LIBC="${2:-glibc}"

TAG="kernel-collector:$(echo "${KERNEL_VERSION}" | tr '.' '_')_${LIBC}"

git clean -d -f -x
docker build -f Dockerfile."${LIBC}" -t "${TAG}" --build-arg KERNEL_VERSION="${KERNEL_VERSION}" ./ | tee prepare.log
docker run -i -t --rm -v "$PWD":/kernel-collector -e DEBUG=1 "${TAG}" | tee build.log
