CC ?= gcc
GO ?= go

LIBBPF = ../libbpf
LIBBPF_READY = ../.local_libbpf/libbpf.a
KERNEL_RELEASE ?= $(shell uname -r)
KERNEL_MAJOR = $(word 1,$(subst ., ,$(KERNEL_RELEASE)))
KERNEL_MINOR = $(word 2,$(subst ., ,$(KERNEL_RELEASE)))
CLANG_MAJOR_VERSION := $(shell clang --version 2>/dev/null | sed -n 's/^.*clang version \([0-9]*\).*/\1/p' | head -n 1)
LIBBPF_CC := $(shell if [ "$(or $(CLANG_MAJOR_VERSION),0)" -ge 8 ]; then printf '%s\n' clang; else printf '%s\n' gcc; fi)
GOCACHE ?= $(shell $(GO) env GOCACHE)
TESTER_BIN = legacy_test
GO_TESTER_BIN = ../gotests/go_tester
TESTER_SRCS = tester_user.c tester_dns.c tester_socket.c
GO_TESTER_SRCS = $(wildcard ../gotests/*.go ../gotests/go.mod ../gotests/go.sum)
TESTER_DEBUG_CFLAGS ?= -g
GO_TESTER_GCFLAGS ?= all=-dwarf=true
GO_TESTER_CGO_CFLAGS ?= -g

.PHONY: all tester legacy-tester go-tester clean FORCE

all: tester

tester: legacy-tester go-tester

legacy-tester: $(TESTER_BIN)

go-tester: $(GO_TESTER_BIN)

ifneq ($(strip $(MAKECMDGOALS)),clean)
ifeq ($(KERNEL_MAJOR).$(KERNEL_MINOR),3.10)
$(error The testers require libbpf 1.x and do not support kernel 3.10; use the prebuilt CentOS 7 objects)
endif
endif

# Refresh the installed headers and library together; libbpf's build is incremental.
$(LIBBPF_READY): FORCE
	$(MAKE) -C "$(LIBBPF)/src" \
		CC=$(LIBBPF_CC) CFLAGS="-fPIE" BUILD_STATIC_ONLY=1 \
		DESTDIR=../../.local_libbpf INCLUDEDIR= LIBDIR= UAPIDIR= \
		install install_uapi_headers

FORCE:

$(TESTER_BIN): $(TESTER_SRCS) $(LIBBPF_READY)
	$(CC) $(CFLAGS) $(TESTER_DEBUG_CFLAGS) -I../.local_libbpf -L../.local_libbpf -o $@ $(TESTER_SRCS) -lbpf -lz -lelf -pthread

$(GO_TESTER_BIN): $(GO_TESTER_SRCS) $(LIBBPF_READY)
	cd ../gotests && env GOCACHE="$(GOCACHE)" CGO_ENABLED=1 CGO_CFLAGS="$(strip $(CGO_CFLAGS) $(GO_TESTER_CGO_CFLAGS))" $(GO) build -buildvcs=false -gcflags="$(GO_TESTER_GCFLAGS)" -o go_tester .

clean:
	rm -f $(TESTER_BIN) $(GO_TESTER_BIN)
