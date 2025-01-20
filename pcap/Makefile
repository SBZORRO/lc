all: 

%.o: %.c
	$(CC) -c $<

hello: main.c client.c flow.c
	$(CC) -o $@ $^ -I. -lpcap

hello.so: main.c
	$(CC) -shared -fPIC -o $@ $< -lpcap

client: client.c
	$(CC) -o $@ $<

clean:
	rm *.o *.a *.so hello client
