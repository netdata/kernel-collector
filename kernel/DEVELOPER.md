# Developers

This MD file was added to help developers starting with eBPF development.

In this repo we are using the same [pattern](https://elixir.bootlin.com/linux/v4.20.17/source/samples/bpf) that was used before
[BTF](https://docs.kernel.org/bpf/btf.html) was released. All source files ending with `_kern.c` are eBPF codes
loaded inside `kernel ring`. We do no have a `_user.c` for each one of `_kern.c` files, because we have a common loader for
all (`tester_user.c`).

## Libbpf

This repo is currently using two libbpf versions. We are using the [latest](https://github.com/netdata/libbpf) for kernels newer
than `4.11`, and we still use version `0.0.9` to support `CentOS 7.9`. The transition between versions is done during compilation
time using a [script](https://github.com/netdata/kernel-collector/blob/master/.dockerfiles/change_libbpf.sh).

## Internal Code division

All eBPF sources are split in three sections:

-  Headers
-  Tables
-  Tracers


### Headers

Netdata headers are defined inside directory `includes/`.

All other headers used in `_kern.c` files are inside kernel source and you can generate them with commands:

```sh
KERNEL_VERSION=`uname -r`
if [ "${KERNEL_VERSION}" !=  "3.10.0-1160.76.1.el7" ]; then
       make defconfig -C /usr/src/linux
else
       make silentoldconfig -C /usr/src/linux
fi   
make scripts -C /usr/src/linux
make prepare -C /usr/src/linux
make headers_install -C /usr/src/linux
```

You can take a look in our [docker image](https://github.com/netdata/kernel-collector/blob/master/Dockerfile.glibc.generic) how
to get specific kernels from [kernel.org](https://kernel.org/).

Our headers always start with prefix `netdata_` and we append the associated `eBPF` code after `_`, the exceptions for this rule
are:

- `netdata_common.h`: that has common functions used inside all eBPF programs;
- `netdata_defs.h`: Constants used inside hash tables
- `netdata_asm_goto.h`: Used to compile old RH kernels.

### Tables

Tables are defined according `LIBBPF` version, but we are defining their declarations according kernel version to avoid
unnecessary headers inside eBPF codes. Thanks this every time you see the preprocessor like this

```sh
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
```

means that we are using codes that will be compiled with latest `libbpf` version.


For all hash tables we are defining:

- Type: We are working with [HASH](https://docs.kernel.org/bpf/map_hash.html) and  [ARRAY](https://docs.kernel.org/bpf/map_array.html)
- Key size: the size in bytes of the key.
- Value size: the size in bytes of the value.
- Max entries: Number of entries expected in the table.

### Tracers

In this repo we use the following tracers:

- probes: They can be `kprobe` or `kretprobe`. The first is added when we wish to monitor calls for the function, while the second
monitors not only the calls, but also returns from functions.
- tracepoints: provides a [hook](https://docs.kernel.org/trace/tracepoints.html) to call functions.

There are other tracers like `uprobe` that we are not working right now, and `trampolines` that we have a specific 
[repo](https://github.com/netdata/ebpf-co-re) for them.

## Binaries

Binaries are compiled in accordance to kernel version, the list of binaries are defined in our 
[Makefile](https://github.com/netdata/kernel-collector/blob/84e70d0ae83cc91fee59053459eff84f9077d2c5/kernel/Makefile#L66-L88).

When needed to compile everything during development, we can run the command:

```sh
make dev
```

## Tests

The tester is not compiled by default. To compile it and run all common tests run:

```sh
make dev
for j in `seq 0 2`; do for i in `ls *.o`; do ./kernel/legacy_test --content --pid $j --load-binary $i --log-path $i_pid$i.txt; 2>> err >> out; done; done
```

You can take a look in all options available for tests running:

```sh
./kernel/legacy_test --help
```

