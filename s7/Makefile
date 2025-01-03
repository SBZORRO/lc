
repl: s7.o
	gcc -o repl repl.c s7.o -Wl,-export-dynamic -lm -I. -ldl
s7.o: s7.c
	gcc -c s7.c -I.

clean:
	rm *.o repl
