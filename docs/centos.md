# CentOS

Our eBPF programs are designed to support down to CentOS 7.

Note that CentOS 7 uses Linux 3.10, and supports eBPF via backporting the code
for it to their distribution's kernel fork.

This introduces some complexities in dealing with the eBPF verifier, as it may
behave very differently than on the latest kernels for some code, and reject
it.

For this reason it is strongly advised to create a VM for CentOS 7 and test
whether the verifier will accept your programs on that platform.

## Setting up CentOS 7

Setting up the environment inside the VM is nearly exactly the same as that
used in the `Dockerfile.glibc.centos7`.

When you run any compilation commands with `make`, you must ensure `make` uses
the correct LLVM toolset as well.
