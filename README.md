# kernel-collector

![CI](https://github.com/netdata/kernel-collector/workflows/CI/badge.svg)
![CD](https://github.com/netdata/kernel-collector/workflows/CD/badge.svg)

Linux Kernel eBPF Collectors

## Directory structure

The respository has the following directory structure:

- `artifacts`: directory that will have the eBPF programs when the compilation
  process ends.
- `co-re`: contains all eBPF programs that utilize eBPF CO-RE (Compile Once -
  Run Everywhere) technology.
    - `tests`: contains test cases for our eBPF CO-RE programs.
- `docs`: contains an assortment of documentation related to this repository.
- `includes`: headers used throughout the project.
- `kernel`: contains all eBPF programs that don't utilize eBPF CO-RE
  technology; these may be considered legacy more and more as time progresses
  and we shift fully to CO-RE.
- `kernel-patches`: contains patches needed to properly compile our legacy
  `kernel/` eBPF programs on some kernel versions.
- `libbpf`: this is a submodule'd fork of
  [netdata/libbpf](https://github.com/netdata/libbpf) which is itself a fork of
  the official `libbpf` package, the user-space side of eBPF system calls.
- `tools`: scripts used to verify system status before installing eBPF code.

## Requirements

#### Packages

To compile the eBPF programs, it will be necessary to have the following
packages:

- libelf headers
- LLVM/Clang; this is because GCC prior to 10.0 cannot compile eBPF code.
- Kernel headers

#### Generating Headers

Kernel headers can be extracted directly from the kernel source doing the
following steps (assumes your kernel source is accessible at `/usr/src/linux`):

```bash
cd /usr/src/linux
make defconfig
make scripts
make prepare
make headers_install
```

#### Misc

In case you are using the kernel `5.4` or newer, please comment out the
following line inside the file `generated/autoconf.h`:

```c
#define CONFIG_CC_HAS_ASM_INLINE 1
```

#### Makefiles

It's also possible that you'll need to change the `Makefile`s in this
repository according your environment. The original files were adjusted to
compile on Slackware Linux Current.

Inside `kernel/Makefile`, you may need to change the following variables:

- `KERNELSOURCE`: Where is your kernel-source? This variable was set initially
  to work on Slackware, Fedora and Ubuntu.
- `LINUXINCLUDE`: Depending on the Linux distribution, it may be necessary to
  add or remove directories from this variable.
- `LLVM_INCLUDES`: Depending on the kernel version, it may be necessary to
  change this path.

## Building with Docker

There are two build environments that produce different variants of libc and
the Linux Kernel.

The build environments are:

- `musl`  => `Dockerfile.musl` (_based on Alpine 3.11_)
- `glibc` => `Dockerfile.glibc` (_based on Ubuntu 20.04_)

### glibc

```sh
$ docker build -f Dockerfile.glibc -t kernel-collector:glibc ./
$ docker run --rm -v $PWD:/kernel-collector kernel-collector:glibc
```

### musl

```sh
$ docker build -f Dockerfile.musl -t kernel-collector:musl ./
$ docker run --rm -v $PWD:/kernel-collector kernel-collector:musl
```

### Different Kernel

To build for a different Kernel version rather than the default just pass the
`--build-arg KERNEL_VERSION=<kernel_version>` argument to the `docker build`.

For example:

```sh
$ docker build -f Dockerfile.musl -t kernel-collector:musl_5_4 --build--arg KERNEL_VERSION=5.4.18 ./
$ docker run --rm -v $PWD:/kernel-collector kernel-collector:musl_5_4
```

### Building with Debug Symbols

To build with debug symbols enabled, set the environment variable `DEBUG` to `1`
when running the build image.

For example:

```sh
$ docker build -f Dockerfile.musl -t kernel-collector:musl ./
$ docker run --rm -e DEBUG=1 -v $PWD:/kernel-collector kernel-collector:musl
```

This sets `EXTRA_CFLAGS=-g` before building.

## Manual Compilation

After you've got your `kernel/Makefille` properly setup, you can run the
following command to compile all the eBPF programs:

```bash
# build in parallel jobs equal to `nproc` (number of processors)
$ make -j`nproc`
```

When compilation finishes, you will have a file inside the `artifacts`
directory with contents like the following:

```
pnetdata_ebpf_process.<kernel version>.o
pnetdata_ebpf_socket.<kernel version>.o
rnetdata_ebpf_process.<kernel version>.o
rnetdata_ebpf_socket.<kernel version>.o
...
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

   Replace `v0.0.1` with the next desired tag. SemVer is not strictly being
   followed here at this time so the specific tagged versions is not so
   important.

   This will kick off a Github Action Workflow that will Rebuild the Netdata
   eBPF Kernel Collector for all Kernel and LIBC variants, create a Github
   Release and upload all assets to the release to be consumed by anyone or the
   Netdata Installer.

2. Wait for the CD pipeline to finish in the Github Actions UI.
3. Review the Release, Updates Release Notes, etc in the Github Releases UI.
4. Push the "Publish Release" button in the Github Releases UI.

## Contribution

Netdata is open-software software and we are always open for contributions that
you can give us.

If you want to contribute an eBPF program, then please be sure that your
program matches the following patterns:

- Your program must run on all kernels since at least kernel `4.11`.
- Write some code that's responsible to measure the latency of your program.
- We have the variable NETDATASEL, that selects where the functions will be
  attached. Be sure that inside your code `0` is associated with `kretprobe`,
  `1` is associated with `kretprobe` and `perf events` and `2` is associated
  with `kprobe`.
