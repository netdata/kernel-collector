# kernel-collector

![CI](https://github.com/netdata/kernel-collector/workflows/CI/badge.svg)
![CD](https://github.com/netdata/kernel-collector/workflows/CD/badge.svg)

Linux Kernel eBPF Collectors

## Directory structure

The respository has the following directory structure:

-   `artifacts`: Directory that will have the eBPF programs and shared libraries when the compilation process ends.
-   `includes`: Common headers
-   `kernel`: The eBPF programs source code
-   `lib`: The libelf static used to create the shared library.
-   `library`: Codes from Linux kernel-source changed to create the shared library.
-   `libbpf_0_0_1`: An inexistent version of the libbpf library, we changed it to support old Linux kernels.
-   `libbpf`: The latest libbpf version from kernel.
-   `tools`: scripts used to verify system status before to install or test any eBPF code.
-   `user`: Software to tests the eBPF program

## Necessary packages

To compile the shared libraries and the eBPF programs, it will be necessary to have the following packages:

-   Libelf headers
-   llvm/clang , because GCC cannot compile eBPF codes.
-   Kernel headers

The last group of files can be extracted direct from kernel source doing the following steps:

```bash
cd /usr/src/linux
make defconfig
make scripts
make prepare
make headers_install
```

Case you are using the kernel `5.4` or newer, it is necessary to comment the following line inside the file 
 `generated/autoconf.h`:

```
#define CONFIG_CC_HAS_ASM_INLINE 1
```

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

### Building with Debug Symbols

To build with debug symbols enabled, set the environment variable `DEBUG` to `1`
when running the build image.

For example:

```sh
$ docker build -f Dodkcerfile.musl -t kernel-collector:musl ./
$ docker run --rm -e DEBUG=1 -v $PWD:/kernel-collector kernel-collector:musl
```

This sets `EXTRA_CFLAGS=-g` up before building.

## Compilation (manually)

After to do the necessaries changes inside the file `kernel/Makefille`, to compile the libraries
 and the eBPF programs, you only need to do the following steps:

```bash
#  cd user
# make
``` 

When the compilation finishes, you will have inside `artificats` directory a file with the following
content:

```
usr/lib64/libbpf_kernel.so
libnetdata_ebpf.so
dnetdata_ebpf_process.o
pnetdata_ebpf_process.o
rnetdata_ebpf_process.o
```

We can group these files as:

-   `libbpf_kernel.so`: This is the libbpf shared library that must be moved to a directory listed inside 
 `/etc/ld.so.conf`, when you move it for one of the directory, it will be necessary to create a symbolic link, 
 for example, let us assume that the distribution uses `/usr/lib64/` to store shared libraries, the following 
commands are necessaries:

```bash
cp usr/lib64/libbpf_kernel.so /usr/lib64/
ln -s /usr/lib64/libbpf_kernel.so /usr/lib64/libbpf_kernel.so.0
```

-   `Collector files`: the collector works with all files created during the compilation, but the next 4 files
need to be copied to `/usr/libexec/netdata/plugins.d` for the collector to have condition to access them:
    -   `libnetdata_ebpf.so`: Shared library used to load the eBPF programs.
    -   `dnetdata_ebpf_process.o`: eBPF program used with developer mode.
    -   `pnetdata_ebpf_process.o`: eBPF program used with entry mode, this is the default mode.
    -   `rnetdata_ebpf_process.o`: eBPF program used with return mode.


After this you can start the new collector `ebpf_program.plugin`.

## Releasing

To release a new version and create a Github Release; create a Git tag like so:

```sh
$ TAG="v0.0.1"; git tag -a -s -m "Release ${TAG}" "${TAG}" && git push origin "${TAG}"
```

Replace `v0.0.1` with the next desired tag. SemVer is not strictly being followed
here at this time so the specific tagged versions is not so important.

This will kick off a Github Action Workflow that will Rebuild the NetData eBPF
Kernel Collector for all Kernel and LIBC variants, create a Github Release and
upload all assets to the release to be consumed by anyone or the NetData Installer.

## Contribution

Netdata is an open-software software and we are always open for contributions that
you can give us.

Case you want do a contribution with an eBPF program, please, be sure that your program
is according with the following patterns:

-   Your program must run on all kernels since at least kernel `4.11`
-   Create an additional code that is responsible to measure the latency of your program.
-   We have the variable NETDATASEL, that selects where the functions will be attached. Be
    sure that inside your code `0` is associated `kretprobe`, `1` is associated with `kretprobe`
    and `perf events` and `2` is assoacited with `kprobe`.
