LIBBPF = ../libbpf
CFLAGS = -Wall -ggdb
INCLUDES = -I../includes/ -I../libbpf/src/ -I./includes/ -I../libbpf -I../libbpf/include/uapi/
CLANG ?= clang 
LLVM_STRIP ?= llvm-strip
OUTPUT = tests/
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
			 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }') 
KERNEL_VERSION="$(shell cat /proc/sys/kernel/osrelease)"
FIRST_KERNEL_VERSION=$(shell sh ../tools/complement.sh "$(KERNEL_VERSION)")
VER_MAJOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f1)
VER_MINOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f2)
VER_PATCH=$(shell echo $(KERNEL_VERSION) | cut -d. -f3)
RUNNING_VERSION_CODE=$(shell echo $$(( $(VER_MAJOR) * 65536 + $(VER_MINOR) * 256 + $(VER_PATCH) )) )

_LIBC ?= glibc

APPS = cachestat \
       filesystem \
       mount \
       process \
       shm \
       swap \
       sync \
       #

all: compress

libbpf:
	cd ../libbpf/src && mkdir -p root build && $(MAKE) BUILD_STATIC_ONLY=1 OBJDIR=build DESTDIR=.. INCLUDEDIR= LIBDIR= UAPIDIR= install \
	&& cp build/*.a ../../co-re/	

%.bpf.o: %.bpf.c libbpf
	$(CLANG) $(INCLUDES) -ggdb -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@ # strip useless DWARF info

%.skel.h: %.bpf.o
	bpftool gen skeleton $< > includes/$@

$(patsubst %,%.o,$(APPS)): %.o: %.skel.h

%.o: %.c 
	$(CLANG) $(CFLAGS) -DMY_LINUX_VERSION_CODE=$(RUNNING_VERSION_CODE) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(APPS): %: %.o 
	$(CLANG) $(CFLAGS) -L. $^ -lelf -lz -lbpf -o $(OUTPUT)$@

compress: $(APPS)
	tar -cf ../artifacts/netdata_ebpf-CO-RE-$(_LIBC).tar includes/*
	if [ "$${DEBUG:-0}" -eq 1 ]; then tar -uvf ../artifacts/netdata_ebpf-CO-RE-$(_LIBC).tar ../tools/check-kernel-core.sh; fi
	xz ../artifacts/netdata_ebpf-CO-RE-$(_LIBC).tar
	( cd ../artifacts; sha256sum netdata_ebpf-CO-RE-$(_LIBC).tar.xz > netdata_ebpf-CO-RE-$(_LIBC).tar.xz.sha256sum )

clean:
	cd ../libbpf/src/ && make clean && rm -rf build root
	rm *.o $(OUTPUT)* libbpf.a includes/*
