# Kernel code

Inside this directory we have the `eBPF programs` source code. Until gcc 10.0 to be released to compile
 these files it will be necessary to use at least the `clang 4.0` and `llvm 4.0`.

## Files

### Makefile

The Makefile uses some commands to define variables, but there is a specific that  you need to change
manually depending of your distribution, the variable `KERNEL_SOURCE`.

### Headers

This directory has two headers:

-  `netdata_asm_goto.h`: This is the header that allows to compile our code on RH 7.x family.
-  `netdata_ebpf.h`: The main header, this header has the common defintions for all `.c` files. 

### Source Code

Right now we have two `eBPF` codes merged:

-  `latency_process_kern.c`: This is an eBPF program that was initially used to measure the collector
 latency;
-  `process_kern.c`: This is the unique collector code merged until now.
