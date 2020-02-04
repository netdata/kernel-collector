CLANG = clang
LLC = llc
#KERNELSOURCE = /usr/src/linux-$(shell uname -r)
KERNELSOURCE = /usr/src/$(shell test -d "/usr/src/kernels/" && echo "kernels/" || echo "linux-")$(shell uname -r)
KERNELBUILD = /lib/modules/$(shell uname -r)-amd64/build/
ARCH = x86

LINUXINCLUDE += -I$(KERNELBUILD)/arch/$(ARCH)/include/generated
LINUXINCLUDE += -I$(KERNELBUILD)/arch/$(ARCH)/include/generated/uapi
LINUXINCLUDE += -I$(KERNELBUILD)/include

##LINUXINCLUDE += -I$(KERNELBUILD)/include/uapi
##LINUXINCLUDE += -I$(KERNELBUILD)/include/generated/uapi
##LINUXINCLUDE += -I$(KERNELBUILD)/arch/$(ARCH)/include
##LINUXINCLUDE += -I$(KERNELBUILD)/arch/$(ARCH)/include/uapi

LINUXINCLUDE += -I$(KERNELSOURCE)/include/generated/uapi
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/uapi
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/generated
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/generated/uapi
LINUXINCLUDE += -I$(KERNELSOURCE)/include
LINUXINCLUDE += -I$(KERNELSOURCE)/include/uapi
LINUXINCLUDE += -include $(KERNELSOURCE)/include/linux/kconfig.h
LINUXINCLUDE += -I../includes

##LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/generated/uapi
##LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/generated
##LINUXINCLUDE += -I$(KERNELSOURCE)/include/generated/uapi

# LLVM_INCLUDES = -I/usr/lib/clang/4.0.1/include/
#LLVM_INCLUDES = -I/usr/lib64/clang/9.0.0/include/
LLVM_INCLUDES = -I/usr/lib64/clang/9.0.1/include/

process_kern.o: process_kern.c

all: process_kern.o

%.o: %.c
	$(CLANG) -S -nostdinc $(LINUXINCLUDE) $(LLVM_INCLUDES) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
	    	-Wno-compare-distinct-pointer-types \
	    	-Wno-gnu-variable-sized-type-not-at-end \
	    	-Wno-tautological-compare \
		-DNETDATASEL=0 \
		-O2 -emit-llvm -c $<
	$(LLC) -march=bpf -filetype=obj -o r$@ $(<:.c=.ll)
	$(CLANG) -S -nostdinc $(LINUXINCLUDE) $(LLVM_INCLUDES) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
	    	-Wno-compare-distinct-pointer-types \
	    	-Wno-gnu-variable-sized-type-not-at-end \
	    	-Wno-tautological-compare \
		-DNETDATASEL=1 \
		-O2 -emit-llvm -c $<
	$(LLC) -march=bpf -filetype=obj -o d$@ $(<:.c=.ll)
	$(CLANG) -S -nostdinc $(LINUXINCLUDE) $(LLVM_INCLUDES) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
	    	-Wno-compare-distinct-pointer-types \
	    	-Wno-gnu-variable-sized-type-not-at-end \
	    	-Wno-tautological-compare \
		-DNETDATASEL=2 \
		-O2 -emit-llvm -c $<
	$(LLC) -march=bpf -filetype=obj -o p$@ $(<:.c=.ll)

clean:
	rm *.o *.ll
