all: libvector.so libvector.a hello main

%.o: %.c
	$(CC) -c $<

hello: hello.c
	$(CC) -o $@ $<

libvector.a: addvec.o multvec.o
	ar rcs $@ $^

libvector.so: addvec.c multvec.c
	$(CC) -shared -fpic -o $@ $^

sum.so: sum.c
	$(CC) -shared -fpic -o $@ $^

main: main.c sum.so
	$(CC) -o $@ $< ./sum.so

clean:
	rm *.o *.a *.so hello
