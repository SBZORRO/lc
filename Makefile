all: libvector.so libvector.a hello

%.o: %.c
	$(CC) -c $<

hello: hello.c
	$(CC) -o $@ $<

libvector.a: addvec.o multvec.o
	ar rcs $@ $^

libvector.so: addvec.c multvec.c
	$(CC) -shared -fpic -o $@ $^

clean:
	rm *.o *.a *.so hello
