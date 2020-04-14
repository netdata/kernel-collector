# Update Libbpf

We have two libbpf ( https://github.com/libbpf/libbpf ) versions in our repository, one we are the mantainer
and we need to do few changes on it, because it is used with old kernel versions, but we are also
updating our repository with the latest version of Libbpf every time a new release is created.

## Libbpf 0.0.1

This is the first version released by Libbpf team that we modified. This version is used to compile any kernel 
 older than `4.15`.  The selection is done inside `library/Makefile` depending on the kernel used to compile 
the library.

We only need to update this directory if we decide to support Kernels older than `4.11`.

## Libbpf

This is the latest version of the library. The update process of this directory is not as simple as overwriting the files,
 because we need to do adjusts the sources and build slightly to avoid compilation errors with older compilers. We also need to change some files inside the library, because we are not using the default shared library name, instead we are renaming it to  `libbpf_kernel.so`.

### Changes inside `src/libbpf.c`

To compile with old versions of `gcc`, we add the following lines inside the file:

```
#include <unistd.h>
// clang-format off
#include <linux/stddef.h>
// clang-format on
#include <endian.h>
```

the position for the lines is very important, this is the motive we are also showing two additional lines ( the first 
 and the last ) to help the developer identify the right position to insert the code.

### Changes inside `src/Makefile`

Inside this file it is necessary we change the `soname` of the library, for the latest version `libbpf`, we change
the following lines:

```
$(OBJDIR)/libbpf.so.$(LIBBPF_VERSION): $(SHARED_OBJS)
        $(CC) -shared -Wl,--version-script=$(VERSION_SCRIPT) \
                      -Wl,-soname,libbpf.so.$(LIBBPF_MAJOR_VERSION) \
                      $^ $(ALL_LDFLAGS) -o $@
```

to

```
$(OBJDIR)/libbpf.so.$(LIBBPF_VERSION): $(SHARED_OBJS)
        $(CC) -shared -Wl,--version-script=$(VERSION_SCRIPT) \
                      -Wl,-soname,libbpf_kernel.so \
                      $^ $(ALL_LDFLAGS) -o $@
```
