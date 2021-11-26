# Tools

This directory contains scripts used to check if the kernel is valid for the
purpose of compiling our eBPF programs, and also for compiling a kernel which
is compatible.

## check-kernel-config.sh

This script is necessary for use to check whether your kernel's configuration
is correct for running eBPF programs.

## check-kernel-core.sh

This script is necessary for use to check whether your kernel's configuration
is correct for running eBPF programs using CO-RE technology.

## build-ebpf-kernel.sh

This script attempts to build a kernel image that has its configuration setup
to run our eBPF programs.
