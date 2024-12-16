#include <stdio.h>

#include "library.h"

int simple() {
  printf("This is main!\n");

  printf("calling myFunction\n");
  int returnVal = myFunction(55);

  printf("calling myFunction2\n");
  struct MyStruct myStruct = myFunction2(returnVal);

  return myStruct.b;
}