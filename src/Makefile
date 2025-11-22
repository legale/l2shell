# single binary for both client and server
BIN_MAIN := l2shell
BIN_DEBUG := l2shell_dbg
BIN_A := a
BIN_B := b
STRIP ?= strip
KMOD_STRIP ?= $(STRIP) --strip-debug
HOSTCC ?= cc
HOSTCFLAGS ?= -O2 -Wall -Wextra
EMBED_HEADER := l2shell_embedded.h
BIN2C := bin2c
BIN2C_SRC := tools/bin2c.c tools/lz4.c

SRC_MAIN := l2shell_main.c
SRC_SERVER := server.c
SRC_CLIENT := client.c
SRC_COMMON := common.c proto.c
SRC_ALL := $(SRC_MAIN) $(SRC_SERVER) $(SRC_CLIENT) $(SRC_COMMON)

CPPFLAGS += -DLINUX -D_GNU_SOURCE -D__USE_MISC -I. -Itests
BASE_CFLAGS := -pipe -Wall -Wextra -Wno-unused-parameter -Wno-unused-const-variable
REL_CFLAGS := $(BASE_CFLAGS) -Os -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-stack-protector
REL_LDFLAGS := -s
DBG_CFLAGS := $(BASE_CFLAGS) -ggdb3
LDFLAGS += -L/usr/local/lib
LDLIBS := -lc
REL_OBJ_DIR := build/release
DBG_OBJ_DIR := build/debug
REL_OBJECTS := $(patsubst %.c,$(REL_OBJ_DIR)/%.o,$(SRC_ALL))
DBG_OBJECTS := $(patsubst %.c,$(DBG_OBJ_DIR)/%.o,$(SRC_ALL))

TEST_DIR := tests
COMMON_TEST_BIN := $(TEST_DIR)/common_tests
TEST_BINARIES := $(COMMON_TEST_BIN)
TEST_LDLIBS := -ldl

# kernel module
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
obj-m += l2shell_kmod.o
KMOD := l2shell_kmod.ko

all: $(BIN_MAIN) $(BIN_DEBUG) $(BIN_A) $(BIN_B) static $(TEST_BINARIES) $(EMBED_HEADER)

$(REL_OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(REL_CFLAGS) -c $< -o $@

$(DBG_OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(DBG_CFLAGS) -c $< -o $@

$(BIN_MAIN): $(REL_OBJECTS)
	$(CC) $(REL_OBJECTS) $(LDFLAGS) $(REL_LDFLAGS) $(LDLIBS) -o $@

$(BIN_DEBUG): $(DBG_OBJECTS)
	$(CC) $(DBG_OBJECTS) $(LDFLAGS) $(LDLIBS) -o $@

$(BIN_A): | $(BIN_MAIN)
	ln -sf $(BIN_MAIN) $(BIN_A)

$(BIN_B): | $(BIN_MAIN)
	ln -sf $(BIN_MAIN) $(BIN_B)

static: $(BIN_MAIN)_static

$(BIN_MAIN)_static: $(REL_OBJECTS)
	$(CC) $(REL_OBJECTS) $(LDFLAGS) $(REL_LDFLAGS) -static -o $(BIN_MAIN)_static
	$(STRIP) $(BIN_MAIN)_static

$(BIN2C): $(BIN2C_SRC)
	$(HOSTCC) $(HOSTCFLAGS) -Itools -o $@ tools/bin2c.c tools/lz4.c

$(EMBED_HEADER): $(BIN_MAIN) $(BIN2C)
	./$(BIN2C) $(BIN_MAIN) $@

$(COMMON_TEST_BIN): tests/common_tests.c common.c proto.c | tests/test_common_shared.h test_util.h common.h proto.h
	$(CC) $(CPPFLAGS) $(DBG_CFLAGS) $^ -o $@ $(TEST_LDLIBS)

clean:
	-@sudo rm -rf build $(BIN_MAIN) $(BIN_DEBUG) $(BIN_MAIN)_static $(BIN_A) $(BIN_B) *.o *.so core *.core *~ $(TEST_BINARIES) logs/* $(EMBED_HEADER) $(BIN2C) || true
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

.PHONY: test-kmod
test-kmod: $(BIN_MAIN) $(KMOD)
	sudo ./scripts/test_kmod.sh

# kmod targets
.PHONY: kmod
kmod: $(KMOD)

$(KMOD): l2shell_kmod.c $(EMBED_HEADER)
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	$(KMOD_STRIP) $(KMOD)

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
