CC=gcc
LIBS =
ifeq ("$(STATIC)","1")
    LIBS= -lbpf -lelfs -lz2
else
    LIBS= -lelfs
endif
LIBBPF_DIR =
LIBBPF_DEST =
LIBRARY_VERSION="libbpf.a" 
LIBRARY_NAME =

#KERNEL_VERSION="$(shell basename $(realpath /usr/src/linux) | cut -f 2 -d '-')"
KERNEL_VERSION="$(shell if [ -f /usr/src/linux/include/config/kernel.release ]; then cat /usr/src/linux/include/config/kernel.release; else cat /proc/sys/kernel/osrelease; fi)"
ON_RC="$(shell if [ -f /etc/redhat-release ]; then cat /etc/redhat-release; else echo "NONE" ; fi)"

VER_MAJOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f1)
VER_MINOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f2)
VER_PATCH=$(shell echo $(KERNEL_VERSION) | cut -d. -f3)

CURRENT_KERNEL=$(shell echo $(VER_MAJOR)\*65536 + $(VER_MINOR)\*256 + $(VER_PATCH) |bc)

ifeq ($(shell test $(CURRENT_KERNEL) -ge 265984; echo $$?),0) # >= 4.15.0
    LIBBPF_DIR = ../libbpf/src
ifeq ("$(STATIC)","1")
    LIBBPF_DEST = ../libbpf/src/root/usr/lib64
else
    LIBRARY_VERSION="libbpf.so.0.0.7"
    LIBBPF_DEST = ../libbpf/src
endif
ifeq ($(ON_RC),"NONE")
    LIBRARY_NAME="libbpf_kernel-7.so"
else
    LIBRARY_NAME="libbpf_kernel-7s.so"
endif

else
    LIBBPF_DIR = ../libbpf_0_0_1/src
ifeq ("$(STATIC)","1")
    LIBBPF_DEST = ../libbpf_0_0_1/src
else
    LIBRARY_VERSION="libbpf.so.0.0.3"
    LIBBPF_DEST = ../libbpf_0_0_1/src/root/usr/lib64
endif
ifeq ($(ON_RC),"NONE")
    LIBRARY_NAME="libbpf_kernel-3.so"
else
    LIBRARY_NAME="libbpf_kernel-3s.so"
endif

endif


OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

override CFLAGS += -I$(LIBBPF_DIR)root/usr/include/ -I../includes -I./ -L../lib/ -L.

override EXTRA_CFLAGS =

all: $(OBJECT_LIBBPF) $(OBJECT_LIBRARY)
ifeq ("$(STATIC)","1")
	cp $(LIBBPF_DEST)/$(LIBRARY_VERSION) $(LIBRARY_VERSION)
else
ifeq ("libbpf.so.0.0.3", "libbpf.so.0.0.3")    
	cp $(LIBBPF_DIR)/$(LIBRARY_VERSION) $(LIBRARY_NAME)
else    
	cp $(LIBBPF_DEST)/$(LIBRARY_VERSION) $(LIBRARY_NAME)
endif	
endif    

ifeq ("$(STATIC)","1")
	$(CC) $(CFLAGS) -I$(LIBBPF_DIR)/root/usr/include/ -I../includes -I./ -L../lib/ -L. $(EXTRA_CFLAGS) $(LDFLAGS) -fPIC -shared -Wl,-soname,libnetdata_ebpf.so.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH),-rpath,'$$ORIGIN' -o libnetdata_ebpf.so.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH) api.c bpf_load.c trace_helpers.c $(LIBS)
else
	$(CC) $(CFLAGS) -I$(LIBBPF_DIR)/root/usr/include/ -I../includes -I./ -L../lib/ -L. $(EXTRA_CFLAGS) $(LDFLAGS) -fPIC -shared -Wl,-soname,libnetdata_ebpf.so.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH),-rpath,'$$ORIGIN' -o libnetdata_ebpf.so.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH) api.c bpf_load.c trace_helpers.c $(LIBS)
endif    

$(OBJECT_LIBBPF): 
ifeq ("$(STATIC)","1")
	cd $(LIBBPF_DIR); \
	mkdir build root; BUILD_STATIC_ONLY=y OBJDIR=build DESTDIR=root $(MAKE) install; $(MAKE) install_headers
else
	cd $(LIBBPF_DIR) && $(MAKE) all; \
	mkdir -p root; DESTDIR=root $(MAKE) install_headers;
endif


clean:
	cd $(LIBBPF_DIR) && $(MAKE) clean;
	rm libnetdata_ebpf.so.$(VER_MAJOR).$(VER_MINOR).$(VER_PATCH)
	rm lib*
ifeq ("$(STATIC)","1")
	rm -rf $(LIBBPF_DIR)/root  $(LIBBPF_DIR)/build
endif
