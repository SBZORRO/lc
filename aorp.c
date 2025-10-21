
#include <stdio.h>

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
valorref (int *ptr)
{
  printf ("%u\n", *ptr);
  printf ("%p\n", ptr);
  printf ("%p\n", &ptr);
  int i = 123;
  ptr = &i;
}

int
main ()
{
  int ii = 123;
  int *ip = &ii;
  printf ("%p\n", &ip);
  printf ("%p\n", ip);
  printf ("%p\n", &ii);
  valorref (ip);
  printf ("%p\n", ip);
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
}
