#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
  char buf[16];
  int res = read(0, buf, 4);
  if (buf[0] == 'T' && buf[1] == 'E' && buf[2] == 'S' && buf[3] == 'T')
    abort();
  return res * 0;
}
