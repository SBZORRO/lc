CC := gcc

# gcc -fanalyzer; clang --analyzer; clang-low-level -Xanalyzer
# CFLAGS := -Wall -I../src
CFLAGS := -Wall -Wextra -Wformat=2 -Wshadow -Werror=return-type -Wconversion -Wsign-conversion -fsanitize=address,undefined -fno-omit-frame-pointer -I../src

SRC := ./src
BLD := ./build
TST := ./test
LOG := $(SRC)/log.c

LDFLAGS += -Wl,-rpath,'$$ORIGIN/lib'

SRCS := $(wildcard $(SRC)/*.c)
# SRCS := $(shell find . -name '*.c')
OBJS := $(patsubst $(SRC)/%.c,$(BLD)/%.o,$(SRCS))
DEPS := $(SRC)/cptr.c $(SRC)/client.c $(SRC)/flow.c $(LOG)/log.c $(SRC)/logger.c $(SRC)/util.c $(SRC)/handler.c

all: $(BLD)/hello

$(BLD)/%.o: $(SRC)/%.c
	$(CC) -c $<

$(BLD)/convar: $(SRC)/convar.c
	$(CC) -o $@ $^

$(BLD)/hello: $(SRC)/main.c $(DEPS)
	$(CC) $(CFLAGS) -g -o $@ $^ -I. -lpcap

$(BLD)/hello2: $(SRC)/main.c $(DEPS)
	$(CC) -o $@ $^ -I./src -I. /lib64/libpcap.so.1

$(BLD)/hello3: $(SRC)/main.c $(DEPS)
	$(CC) $(CFLAGS) -g -o $@ $^ -I. ./libpcap.so.1.9.1 $(LDFLAGS)
$(BLD)/win: $(SRC)/main.c $(DEPS)
	$(CC) $(CFLAGS) -g -o $@ $^ -I../../WpdPack_4_1_2/WpdPack/Include -I../../w64devkit/include -L../../WpdPack_4_1_2/WpdPack/Lib -L../../w64devkit/lib -L. -lwpcap -lws2_32 -lwinpthread

$(BLD)/wintest: $(TST)/test.c $(DEPS)
	$(CC) $(CFLAGS) -g -o $@ $^ -I../../WpdPack_4_1_2/WpdPack/Include -I../../w64devkit/include -L../../WpdPack_4_1_2/WpdPack/Lib -L../../w64devkit/lib -L. -lwpcap -lws2_32 -lwinpthread

$(BLD)/test: $(TST)/test.c $(DEPS)
	$(CC) $(CFLAGS) -g -o $@ $^ -I. -lpcap

$(BLD)/spsc_test: $(TST)/spsc_test.c $(SRC)/spsc_queue.h
	$(CC) $(CFLAGS) -g -o $@ $(TST)/spsc_test.c -I.

$(BLD)/pool_test: $(TST)/pool_test.c $(SRC)/pool.c $(SRC)/pool.h
	$(CC) $(CFLAGS) -g -o $@ $(TST)/pool_test.c $(SRC)/pool.c -I. -pthread

$(BLD)/hello.so: $(SRC)/main.c
	$(CC) -shared -fPIC -o $@ $< -lpcap

$(BLD)/client: $(SRC)/client.c
	$(CC) -o $@ $<

clean:
	rm -rf $(BLD)/*

.PHONY: all clean
