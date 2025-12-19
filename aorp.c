
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void
valorref (int *pi)
{
  *pi = 123;
}
void
aorp (int *ptr, int len)
{
  for (int i = 0; i < len; i++)
    {
      *(ptr + i) = 0;
    }
}

void
pora (int ptr[], int len)
{
  for (int i = 0; i < len; i++)
    {
      ptr[i] = 0;
      //      *ptr = 0;
    }
}

struct point
{
  int x;
  int y;
};

void
takepoint (struct point p)
{
  p.x = 0;
  p.y = 0;
}
void
takepointer (struct point *p)
{
  p->x = 0;
  p->y = 0;
}
struct point
retpoint (struct point *p)
{
  p->x = 123;
  p->y = 123;
  return p[0];
}
struct point *
retpointer (struct point *p)
{
  p->x = 321;
  p->y = 321;
  return p;
}

void
domacro (char *str)
{
  printf ("domacro: %s\n", str);
}

#define TESTMACRO(fun, arg)          \
  do                                 \
    {                                \
      printf ("domacro: %s\n", arg); \
      fun (arg);                     \
    }                                \
  while (0)

int
main ()
{
  int i = 0;
  valorref (&i);
  printf ("%u\n", i);

  int ia[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
  aorp (ia, 10);
  for (int i = 0; i < 10; i++)
    {
      printf ("%u", ia[i]);
    }
  printf ("\n");
  int ib[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
  pora (ib, 10);
  for (int i = 0; i < 10; i++)
    {
      printf ("%u", ib[i]);
    }

  struct point ptr;
  ptr.x = 99;
  ptr.y = 99;
  takepoint (ptr);
  printf ("\n%d,%d", ptr.x, ptr.y);
  takepointer (&ptr);
  printf ("\n%d,%d", ptr.x, ptr.y);

  struct point *p = &ptr;
  printf ("\n%p", p);
  struct point *po = retpointer (p);
  po->x = 333;
  po->y = 333;
  printf ("\n%d,%d", p->x, p->y);
  printf ("\n%p", p);
  struct point pp = retpoint (p);
  pp.x = 111;
  pp.y = 111;
  printf ("\n%d,%d", p->x, p->y);
  printf ("\n%p", &pp);

  printf ("\n\n");

  char *fun = "domacro";
  char *arg = "HELLO WORLD!";
  TESTMACRO (domacro, arg);

  char *addr[]
    = { "10.160.231.152:9999",
        "10.160.231.153:9997",
        "222.222.222.222:222",
        "22.22.22.22:22",
        "111.111.111.111:111",
        "11.11.11.11:11" };
  printf ("sizeof: %lu\n", sizeof (addr));
  printf ("sizeof: %lu\n", sizeof (addr) / sizeof (addr[0]));

  printf ("\n");
  struct point *points = NULL;
  points = malloc (sizeof (struct point) * 10);
  printf ("1: %p\n", points);
  printf ("2: %p\n", *points);
  printf ("3: %p\n", points[0]);
  printf ("4: %p\n", &points);
  printf ("5: %p\n", &points[0]);
  printf ("6: %p\n", &points[1]);
  printf ("7: %p\n", &(points[1]));
  printf ("8: %p\n", (&points)[1]);
  /* printf ("%p\n", &(points + 1)); */
  printf ("9: %p\n", (&points) + 1);
  printf ("a: %p\n", points + 1);
  printf ("\n");

  const char *flow[] = { "123", " ", "abger0[g]", "123", "       ", "1234567" };

  uint8_t *s = "1234567890";
  uint8_t *ss[] = { "1234567890", "123" };
  printf ("sizeof: %u\n", sizeof ("1234567890"));
  printf ("sizeof: %u\n", sizeof (s));
  printf ("sizeof: %u\n", sizeof ((uint8_t *) "1234567890"));
  printf ("sizeof: %u\n", sizeof (ss[0]));
  printf ("sizeof: %u\n", sizeof (ss));
}
