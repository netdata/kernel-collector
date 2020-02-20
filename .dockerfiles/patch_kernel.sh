#!/bin/sh

cd /usr/src/linux || exit 1

for patch in /usr/src/linux-"${KERNEL_VERSION}"-patches/*.diff.gz; do
  zcat "${patch}" | patch -s -t -p 1
done
