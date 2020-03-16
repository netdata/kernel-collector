#!/bin/sh

set -e

srcdir="${1:-/usr/src/linux}"

cd "${srcdir}" || exit

for patch in /usr/src/linux-"${KERNEL_VERSION}"-patches/*.diff.gz; do
  printf >&2 " Patching linux-%s with %s ... " "${KERNEL_VERSION}" "${patch}"
  if zcat < "${patch}" | patch -p 1; then
    echo >&2 " OK"
  else
    echo >&2 " ERR"
  fi
done
