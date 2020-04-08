# Patches

Some Linux kernels that are not LTS and are used on distributions like Ubuntu, does not compile clean, for we 
use them it is necessary to apply some patches on these kernels.

The structure of our Docker file force us to always have a directory for all kernels that we are compiling, case
the kernel does not need a patch, it is necessary to create the directory and insert an empty `.gitclean` file.
