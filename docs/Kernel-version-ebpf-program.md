# Kernel version and eBPF program

In the first versions of the `bpf()` syscall, Linux kernel verified if the eBPF programs that had kprobe
was matching the kernel version, but when the kernel `5.0` was released they removed this check with the
argument it was [useless](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/kernel/bpf/syscall.c?h=v5.0&id=6c4fc209fcf9d27efbaa48368773e4d2bfbd59aa)
, we are copying the text from the link

```
bpf: remove useless version check for prog load
Existing libraries and tracing frameworks work around this kernel
version check by automatically deriving the kernel version from
uname(3) or similar such that the user does not need to do it
manually; these workarounds also make the version check useless
at the same time.

Moreover, most other BPF tracing types enabling bpf_probe_read()-like
functionality have /not/ adapted this check, and in general these
days it is well understood anyway that all the tracing programs are
not stable with regards to future kernels as kernel internal data
structures are subject to change from release to release.

Back at last netconf we discussed [0] and agreed to remove this
check from bpf_prog_load() and instead document it here in the uapi
header that there is no such guarantee for stable API for these
programs.

  [0] http://vger.kernel.org/netconf2018_files/DanielBorkmann_netconf2018.pdf
```

Thanks this description, Netdata took the decision to always give the current kernel version of the kernel
when the `kprobe` is loaded.
