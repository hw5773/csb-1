#include <stdio.h>
#include "../include/debug.h"
#include "../include/defines.h"

int foo(int a);

int main(int argc, char *argv[])
{
  int a;
  const char *b = "Hello, World!";

  imsg("Start the debug test program");
  dmsg("Debug message test");
  imsg("Info message test");
  emsg("Error message test");

  imsg("Invoke the function");
  a = 1;
  foo(a);

  imsg("Test string: %s", b);
  iprint("Test string in hex", b, 0, strlen(b), 10);
  imsg("Finish the debug test program");
  return 0;
}

int foo(int a)
{
  fstart("a: %d", a);
  int ret;
  ret = a + 1;

  dmsg("the value ret is set to %d", ret);

  ffinish("ret: %d", ret);
  return ret;
}
