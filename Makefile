# Компиляция server.c в a и client.c в b
BIN_A = a
BIN_B = b

SRC_A = server.c
SRC_B = client.c

CC     = gcc
FLAGS  += -pipe -Wall -Wextra -Wno-unused-parameter -Wno-unused-const-variable -ggdb3
DEFINE += -DLINUX -D_GNU_SOURCE -D__USE_MISC
INCLUDE = -I /usr/include/
OBJ_A   = $(SRC_A:.c=.o)
OBJ_B   = $(SRC_B:.c=.o)
CFLAGS  += $(FLAGS) $(INCLUDE) $(DEFINE)
LDFLAGS += -L/usr/local/lib
LDLIBS  = -lc

all: $(BIN_A) $(BIN_B) static
	scp  a_static sysadmin@10.241.200.141:/tmp/a
	scp  b_static sysadmin@10.241.200.142:/tmp/b

$(BIN_A): $(OBJ_A)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ_A) $(LDLIBS) -o $(BIN_A)

$(BIN_B): $(OBJ_B)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ_B) $(LDLIBS) -o $(BIN_B)

static: $(BIN_A)_static $(BIN_B)_static

$(BIN_A)_static: $(OBJ_A)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ_A) -static -o $@

$(BIN_B)_static: $(OBJ_B)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ_B) -static -o $@

clean:
	rm -rf $(OBJ_A) $(OBJ_B) $(BIN_A) $(BIN_B) $(BIN_A)_static $(BIN_B)_static *.o *.so core *.core *~
