#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "s7.h"

int
main (int argc, char **argv)
{
  s7_scheme *s7 = s7_init (); /* initialize the interpreter */
  while (1)                   /* fire up a read-eval-print loop */
    {
      char buffer[512];
      fprintf (stdout, "\n> "); /* prompt for input */
      fgets (buffer, 512, stdin);
      if ((buffer[0] != '\n') || (strlen (buffer) > 1))
        { /* evaluate the input and print the result */
          char response[1024];
          snprintf (response, 1024, "(write %s)", buffer);
          s7_eval_c_string (s7, response);
        }
    }
}

/* if not using gcc or clang, make mus-config.h (it can be empty),
 * then
 *
 *   gcc -c s7.c -I.
 *   gcc -o repl repl.c s7.o -lm -I. -ldl
 *
 * run it:
 *
 *    repl
 *    > (+ 1 2)
 *    3
 *    > (define (add1 x) (+ 1 x))
 *    add1
 *    > (add1 2)
 *    3
 *    > (exit)
 *
 * for long-term happiness in linux use:
 *   gcc -o repl repl.c s7.o -Wl,-export-dynamic -lm -I. -ldl
 *   clang also needs -fPIC I think
 * freebsd:
 *   gcc -o repl repl.c s7.o -Wl,-export-dynamic -lm -I.
 * osx:
 *   gcc -o repl repl.c s7.o -lm -I.
 * openbsd:
 *   clang -o repl repl.c s7.o -I. -fPIC -Wl,-export-dynamic -lm
 */
