CLANG = clang
LLC = llc
KERNELSOURCE = /usr/src/linux
LIBBPF = ../libbpf
LIBBPF_HEADERS = ../.local_libbpf
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

override EXTRA_CFLAGS += -fno-stack-protector
override EXTRA_CFLAGS += -DCONFIG_CC_HAS_ASM_INLINE=0
override EXTRA_CFLAGS += -Wno-microsoft-anon-tag

LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/generated
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/generated/uapi
LINUXINCLUDE += -I$(KERNELSOURCE)/include/generated/uapi
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/uapi
LINUXINCLUDE += -I$(KERNELSOURCE)/include
LINUXINCLUDE += -I$(KERNELSOURCE)/include/linux
LINUXINCLUDE += -I$(KERNELSOURCE)/include/uapi
LINUXINCLUDE += -I$(KERNELSOURCE)

LINUXINCLUDE += -I$(LIBBPF)/src
LINUXINCLUDE += -I$(LIBBPF)/include
LINUXINCLUDE += -I$(LIBBPF_HEADERS)/
LINUXINCLUDE += -include $(KERNELSOURCE)/include/linux/kconfig.h
LINUXINCLUDE += -I../includes

CLANG_VERSION := $(shell clang --version | grep -o -E 'clang version [0-9]+\.[0-9]+\.[0-9]' | cut -f 3 -d ' ')
CLANG_MAJOR_VERSION := $(shell echo $(CLANG_VERSION) | cut -d. -f1 )
LLVM_INCLUDES = $(shell [ -d /usr/lib/clang ] && echo "-I/usr/lib/clang/$(CLANG_VERSION)/include" || echo "-I/usr/lib64/clang/$(CLANG_VERSION)/include")
LLVM_INCLUDES += -I/opt/rh/llvm-toolset-7.0/root/usr/lib64/clang/$(CLANG_VERSION)/include

# Kernel sources include shared collector headers directly. Keep generated
# objects in sync when one of those headers changes.
NETDATA_KERNEL_HEADERS := $(wildcard ../includes/*.h)

#KERNEL_VERSION="$(shell basename $(realpath $(KERNELSOURCE)) | cut -f 2 -d '-')"
KERNEL_VERSION := $(shell cat $(KERNELSOURCE)/include/config/kernel.release 2>/dev/null)

ifeq ($(strip $(MAKECMDGOALS)),clean)
CURRENT_KERNEL := 0
else
CURRENT_KERNEL := $(shell printf '%s\n' '$(KERNEL_VERSION)' | awk -F'[.-]' '{ if ($$1 !~ /^[0-9]+$$/ || $$2 !~ /^[0-9]+$$/) exit 1; patch = ($$3 ~ /^[0-9]+$$/) ? $$3 : 0; printf "%d\n", $$1 * 65536 + $$2 * 256 + patch }')
endif

VER_MAJOR := $(shell printf '%s\n' '$(KERNEL_VERSION)' | cut -d. -f1)
VER_MINOR := $(shell printf '%s\n' '$(KERNEL_VERSION)' | cut -d. -f2)

ifneq ($(strip $(MAKECMDGOALS)),clean)
ifneq ($(shell printf '%s\n' '$(KERNEL_VERSION)' | awk -F'[.-]' '{ if (($$1 == 3 && $$2 == 10) || $$1 > 4 || ($$1 == 4 && $$2 >= 12)) exit 0; exit 1 }'; echo $$?),0)
$(error Unsupported kernel $(KERNEL_VERSION): supported versions are 3.10 and 4.12 or newer)
endif
endif

KERNEL_AUTO_CONF := $(KERNELSOURCE)/include/config/auto.conf
CONFIG_CC_MS_EXTENSIONS := $(shell sed -n 's/^CONFIG_CC_MS_EXTENSIONS=//p' $(KERNEL_AUTO_CONF) 2>/dev/null)
ifneq ($(strip $(CONFIG_CC_MS_EXTENSIONS)),)
ifeq ($(shell $(CLANG) $(CONFIG_CC_MS_EXTENSIONS) -fsyntax-only -x c /dev/null >/dev/null 2>&1; echo $$?),0)
override EXTRA_CFLAGS += $(CONFIG_CC_MS_EXTENSIONS)
else ifeq ($(shell $(CLANG) -fms-extensions -fsyntax-only -x c /dev/null >/dev/null 2>&1; echo $$?),0)
override EXTRA_CFLAGS += -fms-extensions
else
$(error Kernel requests $(CONFIG_CC_MS_EXTENSIONS), but $(CLANG) supports neither it nor -fms-extensions)
endif
endif

# This build bypasses Kbuild's compiler-capability define required by ftrace.h.
ifeq ($(shell grep -q '^CONFIG_FUNCTION_TRACER=y' $(KERNEL_AUTO_CONF) 2>/dev/null && grep -q '^CONFIG_HAVE_FENTRY=y' $(KERNEL_AUTO_CONF) 2>/dev/null && $(CLANG) -mfentry -fsyntax-only -x c /dev/null >/dev/null 2>&1; echo $$?),0)
override EXTRA_CFLAGS += -DCC_USING_FENTRY
endif

NETDATA_ALL_APPS= btrfs \
    		  cachestat \
    		  dc \
    		  disk \
    		  ext4 \
    		  fd \
    		  fdatasync \
    		  fsync \
    		  dns \
    		  hardirq \
    		  mdflush \
    		  mount \
    		  msync \
    		  network_viewer \
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

# Kernel newer than 6.16.0 ( 397312 = 6 * 65536 + 16 * 256)
ifeq ($(shell test $(CURRENT_KERNEL) -ge 397312 ; echo $$?),0)
NETDATA_APPS= 	swap \
		process \
		#

# Kernel newer than 6.8.0 ( 395264 = 6 * 65536 + 8 * 256)
else ifeq ($(shell test $(CURRENT_KERNEL) -ge 395264 ; echo $$?),0)
NETDATA_APPS= swap \
	      #
# Kernel newer than 5.15.256 ( 331776 = 5 * 65536 + 16 * 256)
else ifeq ($(shell test $(CURRENT_KERNEL) -ge 331776 ; echo $$?),0)
NETDATA_APPS= cachestat \
	      #
# Kernel newer than 5.14.256 ( 331520 = 5 * 65536 + 14 * 256)
else ifeq ($(shell test $(CURRENT_KERNEL) -ge 331520 ; echo $$?),0)
NETDATA_APPS= cachestat \
	      #
# Kernel newer than 5.13.256 ( 331264 = 5 * 65536 + 13 * 256) and smaller than  5.14.256
else ifeq ($(shell test $(CURRENT_KERNEL) -ge 331264 -a  $(CURRENT_KERNEL) -lt 331520 ; echo $$?),0)
NETDATA_APPS= ${NETDATA_ALL_APPS}
# Kernel newer than 5.10.256 ( 330496 = 5 * 65536 + 11 * 256)
else ifeq ($(shell test $(CURRENT_KERNEL) -ge 330496 ; echo $$?),0)
NETDATA_APPS= fd \
	      #
# Kernel newer than 5.9.256  ( 330240 = 5 * 65536 + 10 * 256)
else ifeq ($(shell test $(CURRENT_KERNEL) -ge 330240 ; echo $$?),0)
NETDATA_APPS= btrfs \
	      process \
	      #
else
NETDATA_APPS= ${NETDATA_ALL_APPS}
endif

ifeq ($(shell test $(CLANG_MAJOR_VERSION) -ge 8 ; echo $$?),0)
CC_LIBBPF = clang
else
CC_LIBBPF = gcc
endif

# BPF_MAP_TYPE_RINGBUF requires kernel >= 5.8 (329728 = 5 * 65536 + 8 * 256)
ifeq ($(shell test $(CURRENT_KERNEL) -ge 329728 ; echo $$?),0)
NETDATA_RINGBUF_APPS= cachestat_buffer \
                      dc_buffer \
                      dns_buffer \
                      fd_buffer \
                      socket_buffer \
                      oomkill_buffer \
                      process_buffer \
                      shm_buffer \
                      swap_buffer \
                      vfs_buffer \
                      #
else
NETDATA_RINGBUF_APPS=
endif

# BPF_MAP_TYPE_ARENA requires kernel >= 6.9 (395520 = 6 * 65536 + 9 * 256)
ifeq ($(shell test $(CURRENT_KERNEL) -ge 395520 ; echo $$?),0)
NETDATA_ARENA_APPS= cachestat_arena \
                    dc_arena \
                    dns_arena \
                    fd_arena \
                    socket_arena \
                    oomkill_arena \
                    process_arena \
                    shm_arena \
                    swap_arena \
                    vfs_arena \
                    #
else
NETDATA_ARENA_APPS=
endif

.PHONY: all dev tester libbpf

ifeq ($(VER_MAJOR).$(VER_MINOR),3.10)
ifneq ($(LEGACY_LIBBPF_ACTIVE),1)
LEGACY_LIBBPF_TARGETS := all dev tester libbpf $(NETDATA_ALL_APPS) $(NETDATA_RINGBUF_APPS) $(NETDATA_ARENA_APPS)
.PHONY: $(LEGACY_LIBBPF_TARGETS)

$(LEGACY_LIBBPF_TARGETS):
	@set -e; \
	libbpf_dir=$$(cd "$(LIBBPF)" && pwd -P); \
	libbpf_git() { GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0="$$libbpf_dir" git -C "$$libbpf_dir" "$$@"; }; \
	libbpf_ref=$$(libbpf_git symbolic-ref --quiet --short HEAD || libbpf_git rev-parse HEAD); \
	trap 'libbpf_git checkout --quiet "$$libbpf_ref"' EXIT; \
	libbpf_git checkout --quiet netdata-patch; \
	$(MAKE) LEGACY_LIBBPF_ACTIVE=1 "$@"
else
all: $(NETDATA_APPS) $(NETDATA_RINGBUF_APPS) $(NETDATA_ARENA_APPS)

dev: ${NETDATA_ALL_APPS} ${NETDATA_RINGBUF_APPS} ${NETDATA_ARENA_APPS}
endif
else
all: $(NETDATA_APPS) $(NETDATA_RINGBUF_APPS) $(NETDATA_ARENA_APPS)

dev: ${NETDATA_ALL_APPS} ${NETDATA_RINGBUF_APPS} ${NETDATA_ARENA_APPS}
endif

ifeq ($(VER_MAJOR).$(VER_MINOR),3.10)
ifeq ($(LEGACY_LIBBPF_ACTIVE),1)
libbpf:
	# -fPIE added to be compatible with olders clang/gcc
	$(MAKE) -C $(LIBBPF)/src CC=$(CC_LIBBPF) CFLAGS="-fPIE" BUILD_STATIC_ONLY=1 DESTDIR=../../.local_libbpf INCLUDEDIR= LIBDIR= UAPIDIR= install

tester: libbpf
	cd ../tests && $(MAKE) tester
endif
else
libbpf:
	# -fPIE added to be compatible with olders clang/gcc
	@set -e; \
	libbpf_dir=$$(cd "$(LIBBPF)" && pwd -P); \
	cd "$$libbpf_dir/src"; \
	/bin/bash ../../.dockerfiles/change_libbpf.sh $(VER_MAJOR) $(VER_MINOR); \
	$(MAKE) CC=$(CC_LIBBPF) CFLAGS="-fPIE" BUILD_STATIC_ONLY=1 DESTDIR=../../.local_libbpf INCLUDEDIR= LIBDIR= UAPIDIR= install

tester: libbpf
	cd ../tests && $(MAKE) tester
endif

%_kern.o: %_kern.c $(NETDATA_KERNEL_HEADERS) libbpf
	$(CLANG) $(EXTRA_CFLAGS) -S -nostdinc $(LINUXINCLUDE) $(LLVM_INCLUDES) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
	    	-Wno-compare-distinct-pointer-types \
	    	-Wno-gnu-variable-sized-type-not-at-end \
	    	-Wno-tautological-compare \
		-Wno-duplicate-decl-specifier \
		-Wno-address-of-packed-member \
		-Wno-macro-redefined \
		-fno-asynchronous-unwind-tables \
		-DNETDATASEL=0 \
		-D__BPF_TRACING__ \
		-D__TARGET_ARCH_$(ARCH) \
		-include ../includes/netdata_asm_goto.h \
		-O2 -g -emit-llvm $< -o $(<:.c=.ll)
	$(LLC) -march=bpf -filetype=obj -o r$@ $(<:.c=.ll)
	$(CLANG) $(EXTRA_CFLAGS) -S -nostdinc $(LINUXINCLUDE) $(LLVM_INCLUDES) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-tautological-compare \
		-Wno-duplicate-decl-specifier \
		-Wno-address-of-packed-member \
		-Wno-macro-redefined \
		-fno-asynchronous-unwind-tables \
		-DNETDATASEL=2 \
		-D__BPF_TRACING__ \
		-D__TARGET_ARCH_$(ARCH) \
		-include ../includes/netdata_asm_goto.h \
		-O2 -g -emit-llvm $< -o $(<:.c=.ll)
	$(LLC) -march=bpf -filetype=obj -o p$@ $(<:.c=.ll)
	/bin/bash rename_binaries.sh "$(VER_MAJOR)" "$(VER_MINOR)" "$@"

ifeq ($(VER_MAJOR).$(VER_MINOR),3.10)
ifeq ($(LEGACY_LIBBPF_ACTIVE),1)
$(NETDATA_APPS): %: %_kern.o

${NETDATA_ALL_APPS}: %: %_kern.o

${NETDATA_RINGBUF_APPS}: %: %_kern.o

${NETDATA_ARENA_APPS}: %: %_kern.o
endif
else
$(NETDATA_APPS): %: %_kern.o

${NETDATA_ALL_APPS}: %: %_kern.o

${NETDATA_RINGBUF_APPS}: %: %_kern.o

${NETDATA_ARENA_APPS}: %: %_kern.o
endif

clean:
	cd $(LIBBPF)/src && make clean
	rm -f *.o *.ll
	if [ -f legacy_test ] ; then rm legacy_test; fi
