
#include <stdio.h>
#include <string.h>
int
main ()
{
  char *str1 = "Hello World!";
  printf ("%d %d\n", strlen (str1), sizeof (str1));
  char str2[] = "Hello World!";
  printf ("%d %d\n", strlen (str2), sizeof (str2));

  printf ("%d %d\n", strlen ("Hello World!"),
	        sizeof ("Hello World!"));
  return 0;
}
