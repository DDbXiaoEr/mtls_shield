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

# STATIC=1（默认）：全静态链接，产物自带 libc，不受目标机 glibc 版本限制。
# 需要 libbpf/libelf/libz/libssl/libcrypto 的静态库（各发行版的 -dev 包默认都带）。
# 静态 glibc 的 getaddrinfo 依赖目标机的 NSS 动态模块，所以 --upstream 请直接写 IP。
# 本地开发用 `make STATIC=0` 生成动态链接版本。
STATIC ?= 1

ifeq ($(STATIC),1)
LDFLAGS += -static
# 静态 glibc 的 getaddrinfo 依赖目标机 NSS 模块，静态版本只接受 IP 字面量
CFLAGS += -DMTLS_STATIC_BUILD
LDLIBS := $(shell pkg-config --libs --static libbpf 2>/dev/null || echo '-lbpf -lelf -lz') \
	$(shell pkg-config --libs --static openssl 2>/dev/null || echo '-lssl -lcrypto -lpthread -ldl') \
	-lelf -lz -lpthread
else
LDLIBS := $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf) \
	-lssl -lcrypto -lpthread -lelf -lz
endif

# OpenSSL 3.5+ 的 libcrypto.pc 把静态 jitterentropy 列为依赖，缺库时给出安装提示
JITTERENTROPY_A := $(shell $(CC) -print-file-name=libjitterentropy.a)
ifneq ($(filter -l:libjitterentropy.a,$(LDLIBS)),)
ifeq ($(JITTERENTROPY_A),libjitterentropy.a)
$(warning OpenSSL 3.5+ needs a static jitterentropy; try: sudo apt install libjitterentropy3-dev)
endif
endif

.PHONY: all clean certs demo verify

all: $(TARGET)

$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name mtls_shield_bpf > $@

$(TARGET): $(SRC_DIR)/mtls_shield.c $(SKEL)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC_DIR)/mtls_shield.c $(LDLIBS)

verify: $(TARGET)
	@file $(TARGET)
ifeq ($(STATIC),1)
	@file $(TARGET) | grep -q 'statically linked' || \
		{ echo "error: $(TARGET) is not statically linked"; exit 1; }
	@if readelf -V $(TARGET) 2>/dev/null | grep -q 'GLIBC_'; then \
		echo "error: $(TARGET) still has GLIBC_ symbol versions"; exit 1; \
	fi
else
	@ldd $(TARGET) || true
endif

certs:
	./scripts/gen_certs.sh certs

demo:
	./scripts/demo.sh

clean:
	rm -f $(TARGET) $(BPF_OBJ) $(SKEL) $(VMLINUX)
