# kernel-collector
Linux Kernel eBPF Collectors

## Directory structure

The respository has the following directory structure:

-   `includes`: Common headers
-   `kernel`: The eBPF programs source code
-   `library`: Codes from Linux kernel-source changed to create the shared library.
-   `libbpf_0_0_1`: An inexistent version of the libbpf library, we changed it to support old Linux kernels.
-   `libbpf_0_0_6`: The latest kernel version
-   `user`: Software to tests the eBPF program
