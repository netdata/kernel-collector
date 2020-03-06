#!/bin/sh

rm -v /usr/lib/libnetdata_ebpf.so
rm -v /usr/lib/libbpf_kernel.so
rm -v /usr/lib/libbpf_kernel.so.0
ldconfig
