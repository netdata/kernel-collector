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
	#cp $(KERNEL_DIR)dprocess_kern.o dnetdata_ebpf_process.o
	$(CC) -L. -I../includes/ -o process_monitor process_user.c $(LIBS)
	if [ -f /usr/lib64/libbpf_kernel.so ]; then tar -acf ../artifacts/netdata_ebpf-$(NETDATA_KERNEL_VERSION)-$(_LIBC).tar.xz /usr/lib64/libbpf_kernel.so* libnetdata_ebpf.so [pr]netdata_ebpf_process.o; elif [ -f /usr/lib/libbpf_kernel.so ]; then tar -acf ../artifacts/netdata_ebpf-$(NETDATA_KERNEL_VERSION)-$(_LIBC).tar.xz /usr/lib/libbpf_kernel.so* libnetdata_ebpf.so [pr]netdata_ebpf_process.o; else echo "ERROR: Cannot find libbpf_kernel.so"; exit 1; fi


$(OBJECT_LIBLOAD):
	cd $(LIBLOAD_DIR) && $(MAKE) all;

$(KERNEL_PROGRAM):
	cd $(KERNEL_DIR) && $(MAKE) all;
	cp $(OBJECT_LIBLOAD) libnetdata_ebpf.so

clean:
	cd $(LIBLOAD_DIR) && $(MAKE) clean;
	cd $(KERNEL_DIR) && $(MAKE) clean;
	if [ -h /usr/lib64/libbpf_kernel.so.0 ] ; then rm /usr/lib64/libbpf_kernel.so* ; fi 
	if [ -h /usr/lib/libbpf_kernel.so.0 ] ; then rm /usr/lib/libbpf_kernel.so* ; fi
	if [ -f libnetdata_ebpf.so ] ; then rm libnetdata_ebpf.so; fi
	if [ -f libnetdata.a ] ; then rm libnetdata.a avl.o libnetdata.o ; fi
	if [ -f pnetdata_ebpf_process.o ] ; then rm *netdata_ebpf_process.o; fi
	rm netdata_ebpf_*.tar.xz

install:
	cp *netdata_ebpf_process.o libnetdata_ebpf.so /usr/libexec/netdata/plugins.d/
