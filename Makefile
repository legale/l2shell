# Компиляция server.c в a и client.c в b
BIN_A = a
BIN_B = b

SRC_A = server.c
SRC_B = client.c
SRC_COMMON = common.c
TEST_SCRIPT = ./scripts/test_local.sh

CC     = gcc
FLAGS  += -pipe -Wall -Wextra -Wno-unused-parameter -Wno-unused-const-variable -ggdb3
DEFINE += -DLINUX -D_GNU_SOURCE -D__USE_MISC
INCLUDE = -I/usr/include/ -I. -Itests
OBJ_COMMON = $(SRC_COMMON:.c=.o)
OBJ_A   = $(SRC_A:.c=.o) $(OBJ_COMMON)
OBJ_B   = $(SRC_B:.c=.o) $(OBJ_COMMON)
CFLAGS  += $(FLAGS) $(INCLUDE) $(DEFINE)
LDFLAGS += -L/usr/local/lib
LDLIBS  = -lc

TEST_DIR := tests
COMMON_TEST_BIN := $(TEST_DIR)/common_tests
TEST_BINARIES := $(COMMON_TEST_BIN)
TEST_LDLIBS := -ldl

all: $(BIN_A) $(BIN_B) static
	scp -P 443 a_static sysadmin@93.180.6.180:/tmp/a
	scp -P 443 b_static sysadmin@93.180.6.181:/tmp/b

$(BIN_A): $(OBJ_A)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ_A) $(LDLIBS) -o $(BIN_A)

$(BIN_B): $(OBJ_B)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ_B) $(LDLIBS) -o $(BIN_B)

static: $(BIN_A)_static $(BIN_B)_static

$(BIN_A)_static: $(OBJ_A)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ_A) -static -o $@

$(BIN_B)_static: $(OBJ_B)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ_B) -static -o $@

$(COMMON_TEST_BIN): tests/common_tests.c common.c | tests/test_common_shared.h test_util.h common.h
	$(CC) $(CFLAGS) $^ -o $@ $(TEST_LDLIBS)

clean:
	rm -rf $(OBJ_A) $(OBJ_B) $(BIN_A) $(BIN_B) $(BIN_A)_static $(BIN_B)_static *.o *.so core *.core *~ \
		$(TEST_BINARIES)

.PHONY: test
test: $(BIN_A) $(BIN_B)
	sudo $(TEST_SCRIPT)

.PHONY: test-unit
test-unit: $(TEST_BINARIES)
	@set -e; \
	for target in $(TEST_BINARIES); do \
		echo "[test-unit] $$target"; \
		$$target; \
	done
