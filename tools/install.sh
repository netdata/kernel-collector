#!/bin/sh

cp -v libnetdata_ebpf.so /usr/lib
cp -v ./usr/lib*/libbpf_kernel.so /usr/lib

(
  cd /usr/lib || exit 1
  ln -f -s -v libbpf_kernel.so libbpf_kernel.so.0
)

ldconfig
