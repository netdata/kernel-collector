#!/bin/sh

set -e

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
  log "Usage: $(basename "$0") <kernel_version> [<libc>] [<os>]"
  exit 1
fi

KERNEL_VERSION="${1}"
LIBC="${2:-glibc}"
OS="${3:-generic}"

TAG="kernel-collector:$(echo "${KERNEL_VERSION}" | tr '.' '_')_${LIBC}_${OS}"

# Treat a LIBC=static as a static build (STATIC=1)
if [ "$LIBC" = "static" ]; then
  STATIC=1
  export STATIC
fi

git clean -d -f -x

docker build \
  -f Dockerfile."${LIBC}"."${OS}" \
  -t "${TAG}" \
  --build-arg KERNEL_VERSION="${KERNEL_VERSION}" \
  ./ | tee prepare.log

if [ -t 1 ]; then
  docker run \
    -i -t --rm \
    -v "$PWD":/kernel-collector \
    -w /kernel-collector \
    --security-opt seccomp=unconfined \
    -e DEBUG \
    -e STATIC \
    "${TAG}" | tee build.log
else
  docker run \
    --rm \
    -v "$PWD":/kernel-collector \
    -w /kernel-collector \
    --security-opt seccomp=unconfined \
    -e DEBUG \
    -e STATIC \
    "${TAG}" | tee build.log
fi
