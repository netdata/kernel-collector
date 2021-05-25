# Kernel code

Inside this directory we have the `eBPF programs` source code. Until gcc 10.0 to be released to compile
these files it will be necessary to use at least the `clang 4.0` and `llvm 4.0`.

## Files

### Makefile

The Makefile uses some commands to define variables, but there is a peculiarity. You need to change
the `KERNEL_SOURCE` variable manually depending of your distribution.

### Headers

This directory has two headers:

-  `netdata_asm_goto.h`: This is the header that allows to compile our code on RH 7.x family.
-  `netdata_ebpf.h`: The main header, this header has the common definitions for all `.c` files. 

### Source Code

Right now we have two `eBPF` program collections:

-  `process_kern.c`: eBPF program that provides process, file and VFS stats.
-  `socket_kern.c` : eBPF program that provides network stats;
