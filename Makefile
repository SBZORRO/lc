all: libvector.so libvector.a

%.o: %.c
	$(CC) -c $<

libvector.a: addvec.o multvec.o
	ar rcs $@ $^

libvector.so: addvec.c multvec.c
	$(CC) -shared -fpic -o $@ $^

clean:
	rm *.o *.a *.so
