CLANG = clang
LLC = llc
KERNELSOURCE = /usr/src/linux
ARCH = x86

EXTRA_CFLAGS += -fno-stack-protector

LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/generated
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/generated/uapi
LINUXINCLUDE += -I$(KERNELSOURCE)/include

##LINUXINCLUDE += -I$(KERNELSOURCE)/include/uapi
##LINUXINCLUDE += -I$(KERNELSOURCE)/include/generated/uapi
##LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include
##LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/uapi


LINUXINCLUDE += -I$(KERNELSOURCE)/include/generated/uapi
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/uapi
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/generated
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/generated/uapi
LINUXINCLUDE += -I$(KERNELSOURCE)/include
LINUXINCLUDE += -I$(KERNELSOURCE)/include/uapi
LINUXINCLUDE += -include $(KERNELSOURCE)/include/linux/kconfig.h
LINUXINCLUDE += -I../includes

CLANG_VERSION := $(shell clang --version | grep -o -E '[0-9]+\.[0-9]+\.[0-9]')
LLVM_INCLUDES = -I/usr/lib/clang/$(CLANG_VERSION)/include

process_kern.o: process_kern.c

all: process_kern.o

%.o: %.c
	$(CLANG) $(EXTRA_CFLAGS) -S -nostdinc $(LINUXINCLUDE) $(LLVM_INCLUDES) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
	    	-Wno-compare-distinct-pointer-types \
	    	-Wno-gnu-variable-sized-type-not-at-end \
	    	-Wno-tautological-compare \
		-DNETDATASEL=0 \
		-O2 -emit-llvm -c $<
	$(LLC) -march=bpf -filetype=obj -o r$@ $(<:.c=.ll)
	$(CLANG) $(EXTRA_CFLAGS) -S -nostdinc $(LINUXINCLUDE) $(LLVM_INCLUDES) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
	    	-Wno-compare-distinct-pointer-types \
	    	-Wno-gnu-variable-sized-type-not-at-end \
	    	-Wno-tautological-compare \
		-DNETDATASEL=1 \
		-O2 -emit-llvm -c $<
	$(LLC) -march=bpf -filetype=obj -o d$@ $(<:.c=.ll)
	$(CLANG) $(EXTRA_CFLAGS) -S -nostdinc $(LINUXINCLUDE) $(LLVM_INCLUDES) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
	    	-Wno-compare-distinct-pointer-types \
	    	-Wno-gnu-variable-sized-type-not-at-end \
	    	-Wno-tautological-compare \
		-DNETDATASEL=2 \
		-O2 -emit-llvm -c $<
	$(LLC) -march=bpf -filetype=obj -o p$@ $(<:.c=.ll)

clean:
	rm *.o *.ll
