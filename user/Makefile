CC=gcc

KERNEL_DIR = ../kernel/
KERNEL_PROGRAM = $(KERNEL_DIR)process_kern.o

KERNEL_VERSION="$(shell if [ -f /usr/src/linux/include/config/kernel.release ]; then cat /usr/src/linux/include/config/kernel.release; else cat /proc/sys/kernel/osrelease; fi)"
FIRST_KERNEL_VERSION=$(shell sh ../tools/complement.sh "$(KERNEL_VERSION)")

NETDATA_KERNEL_VERSION=$(shell echo $(KERNEL_VERSION) | tr -s "." "_")

VER_MAJOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f1)
VER_MINOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f2)
VER_PATCH=$(shell echo $(KERNEL_VERSION) | cut -d. -f3)

_LIBC ?= glibc

EXTRA_CFLAGS += -fno-stack-protector

all: $(KERNEL_PROGRAM)
	cp $(KERNEL_DIR)rprocess_kern.o rnetdata_ebpf_process.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH).o
	cp $(KERNEL_DIR)pprocess_kern.o pnetdata_ebpf_process.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH).o
	cp $(KERNEL_DIR)dlatency_process_kern.o dlatency_process_kern.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH).o
	cp $(KERNEL_DIR)rnetwork_viewer_kern.o rnetdata_ebpf_socket.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH).o
	cp $(KERNEL_DIR)pnetwork_viewer_kern.o pnetdata_ebpf_socket.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH).o
	$(CC) $(EXTRA_CFLAGS) -L. -I../includes/ -o process_monitor process_user.c $(LIBS)
	if [ -f pnetdata_ebpf_process.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH).o ]; then tar -cf ../artifacts/netdata_ebpf-$(FIRST_KERNEL_VERSION)_$(NETDATA_KERNEL_VERSION)-$(_LIBC).tar [pr]netdata_ebpf_*.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH).o; else echo "ERROR: Cannot find BPF programs"; exit 1; fi
	if [ "$${DEBUG:-0}" -eq 1 ]; then tar -uvf ../artifacts/netdata_ebpf-$(FIRST_KERNEL_VERSION)_$(NETDATA_KERNEL_VERSION)-$(_LIBC).tar process_monitor ../tools/check-kernel-config.sh; fi
	xz ../artifacts/netdata_ebpf-$(FIRST_KERNEL_VERSION)_$(NETDATA_KERNEL_VERSION)-$(_LIBC).tar
	( cd ../artifacts; sha256sum netdata_ebpf-$(FIRST_KERNEL_VERSION)_$(NETDATA_KERNEL_VERSION)-$(_LIBC).tar.xz > netdata_ebpf-$(FIRST_KERNEL_VERSION)_$(NETDATA_KERNEL_VERSION)-$(_LIBC).tar.xz.sha256sum )

$(KERNEL_PROGRAM):
	cd $(KERNEL_DIR) && $(MAKE) all;

clean:
	if [ -f pnetdata_ebpf_process.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH).o ] ; then rm *.o; fi
	cd $(KERNEL_DIR) && $(MAKE) clean;
	rm ../artifacts/*

install:
	cp *netdata_ebpf_process.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH).o /usr/libexec/netdata/plugins.d/
