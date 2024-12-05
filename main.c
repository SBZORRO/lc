#include <stdio.h>
int sum(int* a, int n);

int array[2] = {1, 2};

int main()
{
  getchar();
  int val = sum(array, 2);
  getchar();
  return val;
}
