BPFTOOL ?= bpftool
CLANG ?= clang
CC ?= cc

SRC_DIR := src
BPF_SRC := $(SRC_DIR)/mtls_shield.bpf.c
BPF_OBJ := $(SRC_DIR)/mtls_shield.bpf.o
SKEL := $(SRC_DIR)/mtls_shield.skel.h
VMLINUX := $(SRC_DIR)/vmlinux.h
TARGET := mtls_shield

MACHINE := $(shell uname -m)
ifeq ($(MACHINE),x86_64)
BPF_ARCH := x86
MULTIARCH := x86_64-linux-gnu
else ifeq ($(MACHINE),aarch64)
BPF_ARCH := arm64
MULTIARCH := aarch64-linux-gnu
else
$(error unsupported architecture: $(MACHINE))
endif

BPF_CFLAGS := -g -O2 -Wall -Wextra -Wno-missing-declarations \
	-target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
	-I/usr/include/$(MULTIARCH)
CFLAGS := -g -O2 -Wall -Wextra -Wno-unused-parameter \
	-Wno-deprecated-declarations -I$(SRC_DIR)
LDLIBS := $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf) \
	-lssl -lcrypto -lpthread -lelf -lz

.PHONY: all clean certs demo

all: $(TARGET)

$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name mtls_shield_bpf > $@

$(TARGET): $(SRC_DIR)/mtls_shield.c $(SKEL)
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/mtls_shield.c $(LDLIBS)

certs:
	./scripts/gen_certs.sh certs

demo:
	./scripts/demo.sh

clean:
	rm -f $(TARGET) $(BPF_OBJ) $(SKEL) $(VMLINUX)
