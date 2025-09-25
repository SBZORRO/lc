
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
      *ptr = 0;
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
int
main ()
{
  int ii = 123;
  int *ip = &ii;
  int ia[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };

  aorp (ia, 10);
  for (int i = 0; i < 10; i++)
    {
      printf ("%u", ia[i]);
    }
  pora (ia, 10);
  for (int i = 0; i < 10; i++)
    {
      printf ("%u", ia[i]);
    }

  struct point ptr;
  ptr.x = 99;
  ptr.y = 99;
  takepoint (ptr);
  printf ("\n%d,%d", ptr.x, ptr.y);
  takepointer (&ptr);
  printf ("\n%d,%d", ptr.x, ptr.y);
}
