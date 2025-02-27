#include <pthread.h>
#include <stdio.h>
void *print_message_function (void *ptr);

int
main ()
{
  pthread_t thread1, thread2;
  char *message1 = "Hello ";
  char *message2 = "World!";
  int iret1, iret2;

  iret1 = pthread_create (&thread1, NULL, print_message_function, message1);
  iret2 = pthread_create (&thread2, NULL, print_message_function, message2);

  pthread_join (thread1, NULL);
  pthread_join (thread2, NULL);
  return 0;
}

void *
print_message_function (void *ptr)
{
  printf ("\n%s \n", (char *) ptr);
}
