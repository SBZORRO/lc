all: hello

%.o: %.c
	$(CC) -c $<

hello: main.c client.c
	$(CC) -o $@ $^ -lpcap

hello.so: main.c
	$(CC) -shared -fPIC -o $@ $< -lpcap

client: client.c
	$(CC) -o $@ $<

clean:
	rm *.o *.a *.so hello
