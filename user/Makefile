CC=gcc
LIBS=-ldl

LIBLOAD_DIR = ../library/
OBJECT_LIBLOAD = $(LIBLOAD_DIR)libnetdata_ebpf.so.1.0

KERNEL_DIR = ../kernel/
KERNEL_PROGRAM = $(KERNEL_DIR)process_kern.o

KERNEL_VERSION=$(shell basename $(realpath /usr/src/linux) | cut -f 2 -d '-' | cut -f 1,2 -d '.')

NETDATA_KERNEL_VERSION=$(shell echo $(KERNEL_VERSION) | tr -s "." "_")

_LIBC ?= glibc

all: $(OBJECT_LIBLOAD) $(KERNEL_PROGRAM)
	cp $(KERNEL_DIR)rprocess_kern.o rnetdata_ebpf_process.o
	cp $(KERNEL_DIR)pprocess_kern.o pnetdata_ebpf_process.o
	cp $(KERNEL_DIR)dprocess_kern.o dnetdata_ebpf_process.o
	if [ -f /usr/lib64/libbpf.so.0 ]; then tar -acf ../artifacts/netdata_ebpf_$(NETDATA_KERNEL_VERSION)-$(_LIBC).tar.xz /usr/lib64/libbpf.so.0 libnetdata_ebpf.so *netdata_ebpf_process.o; fi
	if [ -f /usr/lib/libbpf.so.0 ]; then tar -acf ../artifacts/netdata_ebpf_$(NETDATA_KERNEL_VERSION)-$(_LIBC).tar.xz /usr/lib/libbpf.so.0 libnetdata_ebpf.so *netdata_ebpf_process.o; fi

$(OBJECT_LIBLOAD):
	cd $(LIBLOAD_DIR) && $(MAKE) all;

$(KERNEL_PROGRAM):
	cd $(KERNEL_DIR) && $(MAKE) all;
	if [ -d /usr/lib64 ]; then cp $(LIBLOAD_DIR)libbpf.so /usr/lib64/libbpf.so.0; fi
	#ln -s /usr/lib64/libbpf.so.0 /usr/lib64/libbpf.so 
	if [ -d /usr/lib ]; then cp $(LIBLOAD_DIR)libbpf.so /usr/lib/libbpf.so.0; fi
	cp $(OBJECT_LIBLOAD) libnetdata_ebpf.so

clean:
	cd $(LIBLOAD_DIR) && $(MAKE) clean;
	cd $(KERNEL_DIR) && $(MAKE) clean;
	if [ -h /usr/lib64/libbpf.so.0 ] ; then rm /usr/lib64/libbpf.so* ;\
	    elif [ -h /usr/lib/libbpf.so.0 ] ; then rm /usr/lib/libbpf.so* ; fi
	if [ -f libnetdata_ebpf.so ] ; then rm libnetdata_ebpf.so; fi
	if [ -f libnetdata.a ] ; then rm libnetdata.a avl.o libnetdata.o ; fi
	if [ -f pnetdata_ebpf_process.o ] ; then rm *netdata_ebpf_process.o; fi
	rm netdata_ebpf_*.tar.xz

install:
	cp *netdata_ebpf_process.o libnetdata_ebpf.so /usr/libexec/netdata/plugins.d/
