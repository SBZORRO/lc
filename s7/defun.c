#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "s7.h"



int main(int argc, char **argv) {
  s7_scheme* s7 = s7_init();
  while(1)
    {
      char buffer[1024];
      fprintf(stdout, "\n> ");
      fgets(buffer, 1024, stdin);
      if ((buffer[0] != '\n') || (strlen(buffer) > 1))
        {
          char response[1024];
          snprintf(response, 1024, "(write %s)", buffer);
          s7_eval_c_string(s7, response);
        }
    }
}
