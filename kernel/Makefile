CLANG = clang
LLC = llc
KERNELSOURCE = /usr/src/linux
LIBBPF = ../libbpf
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

EXTRA_CFLAGS += -fno-stack-protector

LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/generated
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/generated/uapi
LINUXINCLUDE += -I$(KERNELSOURCE)/include
LINUXINCLUDE += -I$(KERNELSOURCE)/include/generated/uapi
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/uapi
LINUXINCLUDE += -I$(KERNELSOURCE)/include
LINUXINCLUDE += -I$(KERNELSOURCE)/include/uapi
LINUXINCLUDE += -I$(KERNELSOURCE)

LINUXINCLUDE += -I$(LIBBPF)/src
LINUXINCLUDE += -I$(LIBBPF)/include
LINUXINCLUDE += -I$(LIBBPF)/include/uapi
LINUXINCLUDE += -include $(KERNELSOURCE)/include/linux/kconfig.h
LINUXINCLUDE += -I../includes

CLANG_VERSION := $(shell clang --version | grep -o -E 'clang version [0-9]+\.[0-9]+\.[0-9]' | cut -f 3 -d ' ')
LLVM_INCLUDES = $(shell [ -d /usr/lib/clang ] && echo "-I/usr/lib/clang/$(CLANG_VERSION)/include" || echo "-I/usr/lib64/clang/$(CLANG_VERSION)/include")
LLVM_INCLUDES += -I/opt/rh/llvm-toolset-7.0/root/usr/lib64/clang/$(CLANG_VERSION)/include

#KERNEL_VERSION="$(shell basename $(realpath $(KERNELSOURCE)) | cut -f 2 -d '-')"
KERNEL_VERSION="$(shell cat $(KERNELSOURCE)/include/config/kernel.release)"

VER_MAJOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f1)
VER_MINOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f2)
VER_PATCH=$(shell echo $(KERNEL_VERSION) | cut -d. -f3)

CURRENT_KERNEL=$(shell echo $(VER_MAJOR)\*65536 + $(VER_MINOR)\*256 + $(VER_PATCH) |bc)

NETDATA_ALL_APPS= btrfs \
    		  cachestat \
    		  dc \
    		  disk \
    		  ext4 \
    		  fd \
    		  fdatasync \
    		  fsync \
    		  hardirq \
    		  mdflush \
		  mount \
    		  msync \
    		  nfs \
    		  oomkill \
    		  process \
    		  shm \
    		  socket \
    		  softirq \
    		  sync \
    		  syncfs \
    		  sync_file_range \
    		  swap \
    		  vfs \
    		  xfs \
    		  zfs \
    		  #

# Kernel newer than 5.14.256 ( 331520 = 5 * 65536 + 15 * 256)
ifeq ($(shell test $(CURRENT_KERNEL) -ge 331520 ; echo $$?),0)
NETDATA_APPS= cachestat \
	      #
# Kernel newer than 5.10.256 ( 330496 = 5 * 65536 + 11 * 256)
else ifeq ($(shell test $(CURRENT_KERNEL) -ge 330496 ; echo $$?),0)
NETDATA_APPS= fd \
	      #
# Kernel newer than 5.9.256  ( 330240 = 5 * 65536 + 10 * 256)
else ifeq ($(shell test $(CURRENT_KERNEL) -ge 330496 ; echo $$?),0)
NETDATA_APPS= btrfs \
	      process \
	      #
else
NETDATA_APPS= ${NETDATA_ALL_APPS}
endif

all: $(NETDATA_APPS)

dev: ${NETDATA_ALL_APPS}

libbpf:
	cd $(LIBBPF)/src && $(MAKE) BUILD_STATIC_ONLY=1 DESTDIR=../../.local_libbpf INCLUDEDIR= LIBDIR= UAPIDIR= install \

%_kern.o: %_kern.c
	if [ -w $(KERNELSOURCE)/include/generated/autoconf.h ]; then  if [ "$(CURRENT_KERNEL)" -ge 328448 ]; then sed -i -e 's/\(#define CONFIG_CC_HAS_ASM_INLINE 1\)/\/\/\1/' $(KERNELSOURCE)/include/generated/autoconf.h; fi ; fi
	$(CLANG) $(EXTRA_CFLAGS) -S -nostdinc $(LINUXINCLUDE) $(LLVM_INCLUDES) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
	    	-Wno-compare-distinct-pointer-types \
	    	-Wno-gnu-variable-sized-type-not-at-end \
	    	-Wno-tautological-compare \
	    	-fno-asynchronous-unwind-tables \
		-DNETDATASEL=0 \
		-D__BPF_TRACING__ \
		-D__TARGET_ARCH_$(ARCH) \
		-include ../includes/netdata_asm_goto.h \
		-O2 -g -emit-llvm -c $<
	$(LLC) -march=bpf -filetype=obj -o r$@ $(<:.c=.ll)
	$(CLANG) $(EXTRA_CFLAGS) -S -nostdinc $(LINUXINCLUDE) $(LLVM_INCLUDES) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
	    	-Wno-compare-distinct-pointer-types \
	    	-Wno-gnu-variable-sized-type-not-at-end \
	    	-Wno-tautological-compare \
	    	-fno-asynchronous-unwind-tables \
		-DNETDATASEL=2 \
		-D__BPF_TRACING__ \
		-D__TARGET_ARCH_$(ARCH) \
		-include ../includes/netdata_asm_goto.h \
		-O2 -g -emit-llvm -c $<
	$(LLC) -march=bpf -filetype=obj -o p$@ $(<:.c=.ll)
	/bin/bash rename_binaries.sh "$(VER_MAJOR)" "$(VER_MINOR)" "$@"

$(NETDATA_APPS): %: %_kern.o

${NETDATA_ALL_APPS}: %: %_kern.o

tester: libbpf
	$(CC) -I../.local_libbpf -I$(LIBBPF)/src -I$(LIBBPF)/include -I$(LIBBPF)/include/uapi -L../.local_libbpf -o legacy_test tester.c -lbpf -lz -lelf

clean:
	cd $(LIBBPF)/src && make clean
	rm -f *.o *.ll
	if [ -f legacy_test ] ; then rm legacy_test; fi
