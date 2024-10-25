#include <stdio.h>

#include "library.h"

int myFunction(int x)
{
    printf("%d\n", x);
    return x;
}

int recursiveFunc(int x);
int otherFunction(int x)
{
    x += 5;
    if (x < 10) return otherFunction(x);
    return recursiveFunc(x);
}

int recursiveFunc(int x)
{
    if (x <= 0) return 0;
    return x + otherFunction(x - 1);
}

struct MyStruct myFunction2(int x)
{
    printf("MyStruct %d\n", x);
    struct MyStruct myStruct;
    myStruct.a = recursiveFunc(x);
    myStruct.b = x * 10;
    myStruct.c = "my struct";
    return myStruct;
}