all: hello

%.o: %.c
	$(CC) -c $<

hello: main.c
	$(CC) -o $@ $< -lpcap 

clean:
	rm *.o *.a *.so hello
