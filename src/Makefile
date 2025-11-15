# single binary for both client and server
BIN_MAIN := l2shell
BIN_A := a
BIN_B := b

SRC_MAIN := l2shell_main.c
SRC_SERVER := server.c
SRC_CLIENT := client.c
SRC_COMMON := common.c

CPPFLAGS += -DLINUX -D_GNU_SOURCE -D__USE_MISC -I. -Itests
CFLAGS += -pipe -Wall -Wextra -Wno-unused-parameter -Wno-unused-const-variable -ggdb3
LDFLAGS += -L/usr/local/lib
LDLIBS := -lc

OBJ_COMMON := $(SRC_COMMON:.c=.o)
OBJ_SERVER := $(SRC_SERVER:.c=.o)
OBJ_CLIENT := $(SRC_CLIENT:.c=.o)
OBJ_MAIN := $(SRC_MAIN:.c=.o)
OBJ_ALL := $(OBJ_MAIN) $(OBJ_SERVER) $(OBJ_CLIENT) $(OBJ_COMMON)

TEST_DIR := tests
COMMON_TEST_BIN := $(TEST_DIR)/common_tests
TEST_BINARIES := $(COMMON_TEST_BIN)
TEST_LDLIBS := -ldl

# kernel module
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
obj-m += l2shell_kmod.o
KMOD := l2shell_kmod.ko

all: $(BIN_MAIN) $(BIN_A) $(BIN_B) static $(TEST_BINARIES)

$(BIN_MAIN): $(OBJ_ALL)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(OBJ_ALL) $(LDLIBS) -o $(BIN_MAIN)

$(BIN_A): | $(BIN_MAIN)
	ln -sf $(BIN_MAIN) $(BIN_A)

$(BIN_B): | $(BIN_MAIN)
	ln -sf $(BIN_MAIN) $(BIN_B)

static: $(BIN_MAIN)_static

$(BIN_MAIN)_static: $(OBJ_ALL)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(OBJ_ALL) -static -o $(BIN_MAIN)_static

$(COMMON_TEST_BIN): tests/common_tests.c common.c | tests/test_common_shared.h test_util.h common.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@ $(TEST_LDLIBS)

clean:
	-@sudo rm -rf $(OBJ_ALL) $(BIN_MAIN) $(BIN_MAIN)_static $(BIN_A) $(BIN_B) *.o *.so core *.core *~ $(TEST_BINARIES) logs/* || true
	-@$(MAKE) -C $(KDIR) M=$(PWD) clean || true
	-@sudo rm -f $(KMOD) || true

.PHONY: test
# rely on combined binary
test: $(BIN_MAIN)
	rm -f $(BIN_A) $(BIN_B)
	ln -sf $(PWD)/$(BIN_MAIN) $(BIN_A)
	ln -sf $(PWD)/$(BIN_MAIN) $(BIN_B)
	sudo ./scripts/test_local.sh

.PHONY: test-unit
test-unit: $(TEST_BINARIES)
	@set -e; \
	for target in $(TEST_BINARIES); do \
		echo "[test-unit] $$target"; \
		$$target; \
	done

.PHONY: test-kernel
test-kernel: $(BIN_MAIN) $(KMOD)
	sudo ./scripts/test_kernel.sh

# kmod targets
.PHONY: kmod
kmod: $(KMOD)

$(KMOD): l2shell_kmod.c
	$(MAKE) -C $(KDIR) M=$(PWD) modules

.PHONY: kmod-install
kmod-install: $(KMOD)
	@set -e; \
	dst="/lib/modules/$(shell uname -r)/extra"; \
	sudo mkdir -p "$$dst"; \
	sudo cp -f $(KMOD) "$$dst/"; \
	sudo depmod -a

.PHONY: kmod-load
kmod-load: $(KMOD)
	@set -e; \
	if lsmod | grep -q '^l2shell_kmod'; then sudo rmmod l2shell_kmod; fi; \
	sudo insmod ./$(KMOD) || sudo modprobe l2shell_kmod

.PHONY: kmod-unload
kmod-unload:
	@-sudo rmmod l2shell_kmod || true

.PHONY: kmod-reload
kmod-reload: kmod kmod-unload kmod-load
