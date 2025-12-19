CC := gcc

CFLAGS := -Wall -fsanitize=address,undefined -fno-omit-frame-pointer -I../src

SRC := ./src
BLD := ./build
TST := ./test
LOG := $(SRC)/log.c

SRCS := $(wildcard $(SRC)/*.c)
# SRCS := $(shell find . -name '*.c')
OBJS := $(patsubst $(SRC)/%.c,$(BLD)/%.o,$(SRCS))
DEPS := $(SRC)/pcapimpl.c $(SRC)/client.c $(SRC)/flow.c $(LOG)/log.c $(SRC)/logger.c $(SRC)/util.c

all: $(BLD)/hello

$(BLD)/%.o: $(SRC)/%.c
	$(CC) -c $<

$(BLD)/convar: $(SRC)/convar.c
	$(CC) -o $@ $^

$(BLD)/hello: $(SRC)/main.c $(DEPS)
	$(CC) $(CFLAGS) -g -o $@ $^ -I. -lpcap

$(BLD)/hello2: $(SRC)/main.c $(DEPS)
	$(CC) -o $@ $^ -I../src -I.. /lib64/libpcap.so.1

$(BLD)/test: $(TST)/test.c $(DEPS)
	$(CC) $(CFLAGS) -g -o $@ $^ -I. -lpcap

$(BLD)/hello.so: $(SRC)/main.c
	$(CC) -shared -fPIC -o $@ $< -lpcap

$(BLD)/client: $(SRC)/client.c
	$(CC) -o $@ $<

clean:
	rm -rf $(BLD)/*

.PHONY: all clean
