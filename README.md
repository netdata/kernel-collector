# kernel-collector
Linux Kernel eBPF Collectors

## Directory structure

The respository has the following directory structure:

-   `includes`: Common headers
-   `kernel`: The eBPF programs source code
-   `library`: Codes from Linux kernel-source changed to create the shared library.
-   `libbpf_0_0_1`: An inexistent version of the libbpf library, we changed it to support old Linux kernels.
-   `libbpf`: The latest kernel version
-   `user`: Software to tests the eBPF program


## Necessary changes

Before to compile this repository, it is necessary to change the Makefiles according your environment. The original
files were adjusted to compile on Slackware Linux Current. 


### `kernel/Makefile`

Inside this file probably it will be neecssary to change the following variable:

-   `KERNELSOURCE`: Where is your kernel-source? This variable was set initially to work on Slackware, Fedora and Ubuntu
-   `KERNELBUILD`: Directory where the headers are expected to be stored.
-   `LINUXINCLUDE +=`: Depending of the Linux distribution, it is necessary to add or remove directories from this variable.
-   `LLVM_INCLUDES`: Depending of the kernel version, it will be necessary to change this path


## Building (with Docker)

Just run:

```sh
$ docker run --rm -v $PWD:/kernel-collector -w /kernel-collector alpine:3.11 /bin/sh -c './test.sh' |& tee build.log
```

## Compilation (manually)

To compile the libraries and the eBPF programs, you only need to do the following steps:

```bash
#  cd user
# make
``` 
