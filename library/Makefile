CC=gcc
OPT=-Wall -Werror -Wfatal-errors
LIBS=$(shell find / -type f -name 'libelf.a') -lbpf
LIBBPF_DIR =
LIBRARY_VERSION = 

KERNEL_VERSION="$(shell basename $(realpath /usr/src/linux) | cut -f 2 -d '-')"

VER_MAJOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f1)
VER_MINOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f2)
VER_PATCH=$(shell echo $(KERNEL_VERSION) | cut -d. -f3)

CURRENT_KERNEL=$(shell echo $(VER_MAJOR)\*65536 + $(VER_MINOR)\*256 + $(VER_PATCH) |bc)

ifeq ($(shell test $(CURRENT_KERNEL) -ge 265984; echo $$?),0) # >= 4.15.0
    LIBBPF_DIR = ../libbpf/src/
    LIBRARY_VERSION = 7
else
    LIBBPF_DIR = ../libbpf_0_0_1/src/
    LIBRARY_VERSION = 3
endif


OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

override CFLAGS += -I$(LIBBPF_DIR)root/usr/include/ -I../includes -I./
override LDFLAGS += -L./

all: $(OBJECT_LIBBPF)
	cp $(LIBBPF_DIR)/libbpf.so.0.0.$(LIBRARY_VERSION) libbpf.so
	$(CC) $(CFLAGS) $(LDFLAGS) -fPIC -shared -Wl,-soname,libnetdata_ebpf.so.1 -o libnetdata_ebpf.so.1.0 api.c bpf_load.c trace_helpers.c $(LIBS)

$(OBJECT_LIBBPF): 
	cd $(LIBBPF_DIR) && $(MAKE) all; \
	mkdir -p root; DESTDIR=root $(MAKE) install_headers;


clean:
	cd $(LIBBPF_DIR) && $(MAKE) clean;
	rm libnetdata_ebpf.so.1.0
	rm libbpf.so
