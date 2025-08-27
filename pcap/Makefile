CC := gcc

CFLAGS := -Wall -std=c89 -I../src

SRC := ../src
BUILD := .

SRCS := $(wildcard $(SRC)/*.c)
OBJS := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(SRCS))
DEPS := $(SRC)/pcapimpl.c $(SRC)/client.c $(SRC)/flow.c

all: hello

%.o: $(SRC)/%.c
	$(CC) -c $<

convar: $(SRC)/convar.c
	$(CC) -o $@ $^

hello: $(SRC)/main.c $(DEPS)
	$(CC) -o $@ $^ -I. -lpcap

test: $(SRC)/test.c $(DEPS)
	$(CC) -o $@ $^ -I. -lpcap

hello.so: $(SRC)/main.c
	$(CC) -shared -fPIC -o $@ $< -lpcap

client: $(SRC)/client.c
	$(CC) -o $@ $<

clean:
	rm *.o *.a *.so hello client
