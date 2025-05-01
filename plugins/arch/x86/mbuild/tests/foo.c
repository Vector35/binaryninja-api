// getpid() is implicitly defined. gcc returns unicode quotes around the fn
// name in the error message if LANG is en_US.UTF-8, but ASCII if LANG is
// C.
int foo() {
    return getpid();
}
