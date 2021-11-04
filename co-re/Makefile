LIBBPF = ../libbpf
CFLAGS = -Wall -ggdb
INCLUDES = -I../includes/ -I../libbpf/src/ -I./includes/
CLANG ?= clang 
LLVM_STRIP ?= llvm-strip
OUTPUT = tests/
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
			 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }') 
APPS = syncfs \
       #

all: $(APPS)

libbpf:
	cd ../libbpf/src && mkdir root build && $(MAKE) BUILD_STATIC_ONLY=1 OBJDIR=build DESTDIR=.. INCLUDEDIR= LIBDIR= UAPIDIR=

%.bpf.o: %.bpf.c libbpf
	cp ../libbpf/src/build/*.a .
	$(CLANG) $(INCLUDES) -ggdb -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@ # strip useless DWARF info

%.skel.h: %.bpf.o
	bpftool gen skeleton $< > includes/$@

$(patsubst %,%.o,$(APPS)): %.o: %.skel.h

%.o: %.c 
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(APPS): %: %.o 
	$(CLANG) $(CFLAGS) -L. $^ -lelf -lz -lbpf -o $(OUTPUT)$@

clean:
	cd ../libbpf/src/ && make clean && rm -rf build root
	rm *.o $(OUTPUT)* libbpf.a includes/*
