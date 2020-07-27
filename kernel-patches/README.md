# Patches

For some Linux kernels that are not LTS and are used on distributions like Ubuntu, BPF programs cannot be compiled
cleanly. It is necessary to apply some patches on these kernels in order to use them.

The structure of our Docker file forces us to have a directory for every kernel that we are compiling for. In case
the kernel does not need a patch, it is necessary to create the directory and insert an empty `.gitclean` file.
