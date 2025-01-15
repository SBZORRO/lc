all: hello

%.o: %.c
	$(CC) -c $<

hello: main.c
	$(CC) -o $@ $< -lpcap

hello.so: main.c
	$(CC) -shared -fPIC -o $@ $< -lpcap

clean:
	rm *.o *.a *.so hello
