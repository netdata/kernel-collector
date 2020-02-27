#!/bin/sh

cp -v libnetdata_ebpf.so /usr/lib
cp -v ./usr/lib*/libbpf_kernel.so /usr/lib

(
  cd /usr/lib
  ln -f -s -v libbpf_kernel.so libbpf_kernel.so.0
)
