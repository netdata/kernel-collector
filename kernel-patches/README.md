# Kernel Patches

For some Linux kernels that are not LTS and are used on distributions like
Ubuntu, eBPF programs cannot be compiled cleanly. It is necessary to apply some
patches on these kernels in order to use them.

The structure of our Dockerfile forces us to have a directory for every kernel
that we are compiling for, even if a patch is not needed. If you'd like to add
a new kernel version, please make the directory here as well and insert an
empty `.gitkeep` file.
