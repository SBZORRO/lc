all: hello

%.o: %.c
	$(CC) -c $<

convar: convar.c
	$(CC) -o $@ $^

hello: main.c pcapimpl.c client.c flow.c
	$(CC) -o $@ $^ -I. -lpcap

test: test.c pcapimpl.c client.c flow.c
	$(CC) -o $@ $^ -I. -lpcap

hello.so: main.c
	$(CC) -shared -fPIC -o $@ $< -lpcap

client: client.c
	$(CC) -o $@ $<

clean:
	rm *.o *.a *.so hello client
