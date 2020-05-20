CC=gcc
LIBS=-ldl

LIBLOAD_DIR = ../library/
OBJECT_LIBLOAD = $(LIBLOAD_DIR)libnetdata_ebpf.so

KERNEL_DIR = ../kernel/
KERNEL_PROGRAM = $(KERNEL_DIR)process_kern.o

#KERNEL_VERSION=$(shell basename $(realpath /usr/src/linux) | cut -f 2 -d '-' | cut -f 1,2 -d '.')
KERNEL_VERSION="$(shell if [ -f /usr/src/linux/include/config/kernel.release ]; then cat /usr/src/linux/include/config/kernel.release; else cat /proc/sys/kernel/osrelease; fi)"
FIRST_KERNEL_VERSION=$(shell sh ../tools/complement.sh "$(KERNEL_VERSION)")

NETDATA_KERNEL_VERSION=$(shell echo $(KERNEL_VERSION) | tr -s "." "_")

VER_MAJOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f1)
VER_MINOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f2)
VER_PATCH=$(shell echo $(KERNEL_VERSION) | cut -d. -f3)

_LIBC ?= glibc

EXTRA_CFLAGS += -fno-stack-protector

all: $(OBJECT_LIBLOAD) $(KERNEL_PROGRAM)
	cp $(KERNEL_DIR)rprocess_kern.o rnetdata_ebpf_process.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH).o
	cp $(KERNEL_DIR)pprocess_kern.o pnetdata_ebpf_process.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH).o
	cp $(KERNEL_DIR)dprocess_kern.o dnetdata_ebpf_process.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH).o
	cp $(KERNEL_DIR)dlatency_process_kern.o dlatency_process_kern.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH).o
	$(CC) $(EXTRA_CFLAGS) -L. -I../includes/ -o process_monitor process_user.c $(LIBS)
	$(CC) $(EXTRA_CFLAGS) -L. -I../includes/ -o process_latency latency_process_user.c $(LIBS)
	$(CC) $(EXTRA_CFLAGS) -pthread -L. -I../includes/ -o process_test latency_test.c $(LIBS)
ifneq ("$(STATIC)","1")
	if [ -f libnetdata_ebpf.so.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH) ]; then tar -cf ../artifacts/netdata_ebpf-$(FIRST_KERNEL_VERSION)_$(NETDATA_KERNEL_VERSION)-$(_LIBC).tar $(LIBLOAD_DIR)libbpf_kernel*.so libnetdata_ebpf.so.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH) [pr]netdata_ebpf_process.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH).o; else echo "ERROR: Cannot find libbpf_kernel.so"; exit 1; fi
else
	if [ -f libnetdata_ebpf.so.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH) ]; then tar -cf ../artifacts/netdata_ebpf-$(FIRST_KERNEL_VERSION)_$(NETDATA_KERNEL_VERSION)-$(_LIBC).tar libnetdata_ebpf.so.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH) [pr]netdata_ebpf_process.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH).o; else echo "ERROR: Cannot find necessary libraries."; exit 1; fi
endif    
	if [ "$${DEBUG:-0}" -eq 1 ]; then tar -uvf ../artifacts/netdata_ebpf-$(FIRST_KERNEL_VERSION)_$(NETDATA_KERNEL_VERSION)-$(_LIBC).tar dnetdata_ebpf_process.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH).o process_latency process_monitor process_test ../tools/check-kernel-config.sh ../tools/install.sh ../tools/uninstall.sh; fi
	xz ../artifacts/netdata_ebpf-$(FIRST_KERNEL_VERSION)_$(NETDATA_KERNEL_VERSION)-$(_LIBC).tar
	( cd ../artifacts; sha256sum netdata_ebpf-$(FIRST_KERNEL_VERSION)_$(NETDATA_KERNEL_VERSION)-$(_LIBC).tar.xz > netdata_ebpf-$(FIRST_KERNEL_VERSION)_$(NETDATA_KERNEL_VERSION)-$(_LIBC).tar.xz.sha256sum )

$(OBJECT_LIBLOAD):
	cd $(LIBLOAD_DIR) && $(MAKE) all;

$(KERNEL_PROGRAM):
	cd $(KERNEL_DIR) && $(MAKE) all;
	cp $(OBJECT_LIBLOAD)* .

clean:
	cd $(LIBLOAD_DIR) && $(MAKE) clean;
	cd $(KERNEL_DIR) && $(MAKE) clean;
	if [ -f libnetdata_ebpf.so.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH) ] ; then rm libnetdata_ebpf.so.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH); fi
	if [ -f libnetdata.a ] ; then rm libnetdata.a avl.o libnetdata.o ; fi
	if [ -f pnetdata_ebpf_process.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH).o ] ; then rm *.o; fi
	rm ../artifacts/*

install:
	cp *netdata_ebpf_process.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH).o libnetdata_ebpf.so.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH) /usr/libexec/netdata/plugins.d/
