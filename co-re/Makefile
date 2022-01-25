LIBBPF = ../libbpf
CFLAGS = -Wall -ggdb
INCLUDES = -I../.local_libbpf/ -I../includes/ -I$(LIBBPF)/src/ -I./includes/ -I. -I$(LIBBPF)/include/uapi/
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
VER_PATCH=$(shell echo $(KERNEL_VERSION) | cut -d. -f3 | cut -d\- -f1)
RUNNING_VERSION_CODE=$(shell echo $$(( $(VER_MAJOR) * 65536 + $(VER_MINOR) * 256 + $(VER_PATCH))) )

_LIBC ?= glibc

APPS = cachestat \
       dc \
       disk \
       fd \
       filesystem \
       hardirq \
       mdflush \
       mount \
       oomkill \
       process \
       shm \
       socket \
       softirq \
       swap \
       sync \
       vfs \
       #

all: compress

libbpf:
	cd $(LIBBPF)/src && $(MAKE) BUILD_STATIC_ONLY=1 DESTDIR=../../.local_libbpf INCLUDEDIR= LIBDIR= UAPIDIR= install \

%.bpf.o: %.bpf.c libbpf
	$(CLANG) $(INCLUDES) -ggdb -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@ # strip useless DWARF info

%.skel.h: %.bpf.o
	bpftool gen skeleton $< > includes/$@

$(patsubst %,%.o,$(APPS)): %.o: %.skel.h

%.o: %.c 
	$(CC) $(CFLAGS) -DMY_LINUX_VERSION_CODE=$(RUNNING_VERSION_CODE) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(APPS): %: %.o 
	$(CC) $(CFLAGS) -L../.local_libbpf $^ -lbpf -lelf -lz -o $(OUTPUT)$@

compress: $(APPS)
	tar -cf ../artifacts/netdata_ebpf-CO-RE-$(_LIBC).tar includes/*
	if [ "$${DEBUG:-0}" -eq 1 ]; then tar -uvf ../artifacts/netdata_ebpf-CO-RE-$(_LIBC).tar ../tools/check-kernel-core.sh; fi
	xz -f ../artifacts/netdata_ebpf-CO-RE-$(_LIBC).tar
	( cd ../artifacts; sha256sum netdata_ebpf-CO-RE-$(_LIBC).tar.xz > netdata_ebpf-CO-RE-$(_LIBC).tar.xz.sha256sum )

clean:
	rm -f ../artifacts/netdata_ebpf-CO-RE-*.tar.xz
	rm -f ../artifacts/netdata_ebpf-CO-RE-*.tar.xz.sha256sum
	cd $(LIBBPF)/src/ && make clean
	cd $(OUTPUT) && find . -type f ! -name '*.sh' ! -name '.git*'  -delete
	rm -f *.o includes/*
