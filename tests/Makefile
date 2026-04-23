CC ?= gcc
GO ?= go

LIBBPF = ../libbpf
LIBBPF_READY = ../.local_libbpf/libbpf.a
TESTER_BIN = legacy_test
GO_TESTER_BIN = ../gotests/go_tester
TESTER_SRCS = tester_user.c tester_dns.c
GO_TESTER_SRCS = $(wildcard ../gotests/*.go ../gotests/go.mod ../gotests/go.sum)
TESTER_DEBUG_CFLAGS ?= -g
GO_TESTER_GCFLAGS ?= all=-dwarf=true
GO_TESTER_CGO_CFLAGS ?= -g

.PHONY: all tester legacy-tester go-tester clean

all: tester

tester: legacy-tester go-tester

legacy-tester: $(TESTER_BIN)

go-tester: $(GO_TESTER_BIN)

$(LIBBPF_READY):
	$(MAKE) -C ../kernel libbpf

$(TESTER_BIN): $(TESTER_SRCS) $(LIBBPF_READY)
	$(CC) $(CFLAGS) $(TESTER_DEBUG_CFLAGS) -I../.local_libbpf -I$(LIBBPF)/src -I$(LIBBPF)/include -I$(LIBBPF)/include/uapi -L../.local_libbpf -o $@ $(TESTER_SRCS) -lbpf -lz -lelf

$(GO_TESTER_BIN): $(GO_TESTER_SRCS) $(LIBBPF_READY)
	cd ../gotests && env GOCACHE=/tmp/go-cache CGO_ENABLED=1 CGO_CFLAGS="$(strip $(CGO_CFLAGS) $(GO_TESTER_CGO_CFLAGS))" $(GO) build -buildvcs=false -gcflags="$(GO_TESTER_GCFLAGS)" -o go_tester .

clean:
	rm -f $(TESTER_BIN) $(GO_TESTER_BIN)
