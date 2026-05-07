CLANG   ?= clang
BPFTOOL ?= bpftool
CC      ?= gcc

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86

.PHONY: all clean

all: deny_af_alg

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# 1. Compile BPF object
deny_af_alg.bpf.o: deny_af_alg.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# 2. Generate skeleton header from BPF object
deny_af_alg.skel.h: deny_af_alg.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# 3. Compile userspace binary (skeleton header must exist first)
deny_af_alg: deny_af_alg.user.c deny_af_alg.skel.h
	$(CC) -g -O2 -Wall $< -o $@ -lbpf -lelf -lz

clean:
	rm -f *.o *.skel.h deny_af_alg vmlinux.h
