CC=gcc
LIBS=-lelfs
LIBBPF_DIR =
LIBRARY_VERSION = 
LIBRARY_NAME =

#KERNEL_VERSION="$(shell basename $(realpath /usr/src/linux) | cut -f 2 -d '-')"
KERNEL_VERSION="$(shell if [ -f /usr/src/linux/include/config/kernel.release ]; then cat /usr/src/linux/include/config/kernel.release; else cat /proc/sys/kernel/osrelease; fi)"
ON_RC="$(shell if [ -f /etc/redhat-release ]; then cat /etc/redhat-release; else echo "NONE" ; fi)"

VER_MAJOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f1)
VER_MINOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f2)
VER_PATCH=$(shell echo $(KERNEL_VERSION) | cut -d. -f3)

CURRENT_KERNEL=$(shell echo $(VER_MAJOR)\*65536 + $(VER_MINOR)\*256 + $(VER_PATCH) |bc)

ifeq ($(shell test $(CURRENT_KERNEL) -ge 265984; echo $$?),0) # >= 4.15.0
    LIBBPF_DIR = ../libbpf/src/
    LIBRARY_VERSION="libbpf.so.0.0.7"
ifeq ($(ON_RC),"NONE")
    LIBRARY_NAME="libbpf_kernel-7.so"
    LIBS += -lbpf_kernel-7
else
    LIBRARY_NAME="libbpf_kernel-7s.so"
    LIBS += -lbpf_kernel-7s
endif

else
    LIBBPF_DIR = ../libbpf_0_0_1/src/
    LIBRARY_VERSION="libbpf.so.0.0.3"
ifeq ($(ON_RC),"NONE")
    LIBRARY_NAME="libbpf_kernel-3.so"
    LIBS += -lbpf_kernel-3 
else
    LIBRARY_NAME="libbpf_kernel-3s.so"
    LIBS += -lbpf_kernel-3s 
endif

endif


OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

override CFLAGS += -I$(LIBBPF_DIR)root/usr/include/ -I../includes -I./ -L../lib/ -L.

override EXTRA_CFLAGS =

all: $(OBJECT_LIBBPF)
	cp $(LIBBPF_DIR)/$(LIBRARY_VERSION) $(LIBRARY_NAME)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(LDFLAGS) -fPIC -shared -Wl,-soname,libnetdata_ebpf.so.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH),-rpath,'$$ORIGIN' -o libnetdata_ebpf.so.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH) api.c bpf_load.c trace_helpers.c $(LIBS)

$(OBJECT_LIBBPF): 
	cd $(LIBBPF_DIR) && $(MAKE) all; \
	mkdir -p root; DESTDIR=root $(MAKE) install_headers;


clean:
	cd $(LIBBPF_DIR) && $(MAKE) clean;
	rm libnetdata_ebpf.so.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH)
