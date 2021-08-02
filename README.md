# kernel-collector

![CI](https://github.com/netdata/kernel-collector/workflows/CI/badge.svg)
![CD](https://github.com/netdata/kernel-collector/workflows/CD/badge.svg)

Linux Kernel eBPF Collectors

## Directory structure

The respository has the following directory structure:

- `artifacts`: Directory that will have the eBPF programs when the compilation
  process ends.
- `includes`: Common headers
- `kernel`: The eBPF programs source code
- `tools`: scripts used to verify system status before installing eBPF code.

## Necessary packages

To compile the eBPF programs, it will be necessary to have the following packages:

- Libelf headers
- llvm/clang, because GCC prior to 10.0 cannot compile eBPF code.
- Kernel headers

The last group of files can be extracted directly from kernel source doing the
following steps:

```bash
# go into your official linux kernel source code
cd /usr/src/linux
make defconfig
make scripts
make prepare
make headers_install
```

In case you are using the kernel `5.4` or newer, it is necessary to comment out
the following line inside the file `generated/autoconf.h`:

```c
#define CONFIG_CC_HAS_ASM_INLINE 1
```

## Necessary changes

Before compilation of this repository, it is necessary to change the Makefiles
according your environment. The original files were adjusted to compile on
Slackware Linux Current.

### `kernel/Makefile`

Inside this file probably it will be necessary to change the following variable:

- `KERNELSOURCE`: Where is your kernel-source? This variable was set initially
  to work on Slackware, Fedora and Ubuntu
- `LINUXINCLUDE`: Depending of the Linux distribution, it is necessary to add
  or remove directories from this variable.
- `LLVM_INCLUDES`: Depending of the kernel version, it will be necessary to
  change this path

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

After the necessary changes have been done inside the `kernel/Makefille` file,
you need to run the following command to compile the eBPF programs:

```bash
$ make
```

When the compilation finishes, you will have a file inside `artifacts` directory with the following
content:

```
pnetdata_ebpf_process.<kernel version>.o
pnetdata_ebpf_socket.<kernel version>.o
rnetdata_ebpf_process.<kernel version>.o
rnetdata_ebpf_socket.<kernel version>.o
```

`p*.o`: eBPF programs used with entry mode, this is the default mode.
`r*.o`: eBPF programs used with return mode.

These files have to be copied to your plugins directory, which is usually at
`/usr/libexec/netdata/plugins.d/`, for the collector to be able to access them.
After this you can start the new collector `ebpf_program.plugin`.

## Releasing

To release a new version and create a Github Release:

1. Create a Git tag like so:

```sh
$ TAG="v0.0.1"; git tag -a -s -m "Release ${TAG}" "${TAG}" && git push origin "${TAG}"
```

Replace `v0.0.1` with the next desired tag. SemVer is not strictly being followed
here at this time so the specific tagged versions is not so important.

This will kick off a Github Action Workflow that will Rebuild the NetData eBPF
Kernel Collector for all Kernel and LIBC variants, create a Github Release and
upload all assets to the release to be consumed by anyone or the NetData Installer.

2. Wait for the CD pipeline to finish in the Github Actions UI.
3. Review the Release, Updates Release Notes, etc in the Github Releases UI.
4. Push the "Publish Release" button in the Github Releases UI.

## Contribution

Netdata is an open-software software and we are always open for contributions that
you can give us.

Case you want do a contribution with an eBPF program, please, be sure that your program
is according with the following patterns:

- Your program must run on all kernels since at least kernel `4.11`
- Create an additional code that is responsible to measure the latency of your
  program.
- We have the variable NETDATASEL, that selects where the functions will be
  attached. Be sure that inside your code `0` is associated `kretprobe`, `1` is
  associated with `kretprobe` and `perf events` and `2` is assoacited with
  `kprobe`.
