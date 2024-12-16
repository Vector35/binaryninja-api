#pragma once

struct MyStruct {
  int a;
  int b;
  const char* c;
  struct MyStruct* d;
};

int myFunction(int x);
struct MyStruct myFunction2(int x);