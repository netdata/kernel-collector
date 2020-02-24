#!/bin/sh

cd /usr/src/linux || exit 1

for patch in /usr/src/linux-"${KERNEL_VERSION}"-patches/*.diff.gz; do
  printf >&2 " Patching linux-%s with %s ... " "${KERNEL_VERSION}" "${patch}"
  if zcat "${patch}" | patch -s -t -p 1; then
    echo >&2 " OK"
  else
    echo >&2 " ERR"
  fi
done
