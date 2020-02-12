# kernel-collector

![CI](https://github.com/netdata/kernel-collector/workflows/CI/badge.svg)

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

There are two build environments that produce different builds different
variants of libc and the Linux Kernel.

The build environments are:

- `musl`  => `Dockerfile.musl` (_based on Alpine 3.11_)
- `glibc` => `Dockerfile.glibc` (_based on Ubuntu 20.04_)

### Building for glibc

```sh
$ docker build -f Dodkcerfile.glibc -t kernel-collector:glibc ./
$ docker run --rm -v $PWD:/kernel-collector kernel-collector:glibc
```

### Building for musl

```sh
$ docker build -f Dodkcerfile.musl -t kernel-collector:musl ./
$ docker run --rm -v $PWD:/kernel-collector kernel-collector:musl
```

### Building for a Kernel

To build for a different Kernel version other than the default just pass the
`--build-arg KERNEL_VERSION=<kernel_version>` argument to the `docker build`.

For example:

```sh
$ docker build -f Dodkcerfile.musl -t kernel-collector:musl_5_4 --build--arg KERNEL_VERSION=5.4.18 ./
$ docker run --rm -v $PWD:/kernel-collector kernel-collector:musl_5_4
```

## Compilation (manually)

To compile the libraries and the eBPF programs, you only need to do the following steps:

```bash
#  cd user
# make
``` 
