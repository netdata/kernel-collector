CC ?= gcc

LIBBPF = ../libbpf
TESTER_BIN = legacy_test
TESTER_SRCS = tester_user.c tester_dns.c

.PHONY: all tester libbpf clean

all: tester

tester: $(TESTER_BIN)

libbpf:
	$(MAKE) -C ../kernel libbpf

$(TESTER_BIN): $(TESTER_SRCS) libbpf
	$(CC) -I../.local_libbpf -I$(LIBBPF)/src -I$(LIBBPF)/include -I$(LIBBPF)/include/uapi -L../.local_libbpf -o $@ $(TESTER_SRCS) -lbpf -lz -lelf

clean:
	rm -f $(TESTER_BIN)
