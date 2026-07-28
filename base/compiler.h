// Copyright (c) 2026 Vector 35 Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#pragma once

// Compiler-related defines

// BN_DEPRECATED(msg) or BN_DEPRECATED(msg, replacement)
//
// Marks a declaration as deprecated with a message and optional replacement.
//
// For Clang with a replacement, expands to __attribute__((deprecated(msg, replacement)))
// which provides both the deprecation message and a fix-it hint for the replacement.
//
// Otherwise, expands to [[deprecated(msg)]].

#define __BN_DEPRECATED_WITH_MESSAGE(msg) [[deprecated(msg)]]
#if defined(__clang__)
#define __BN_DEPRECATED_WITH_REPLACEMENT(msg, replacement) __attribute__((deprecated(msg, replacement)))
#else
#define __BN_DEPRECATED_WITH_REPLACEMENT(msg, replacement) [[deprecated(msg)]]
#endif

#define __BN_DEPRECATED_GET_MACRO(_1, _2, NAME, ...) NAME
#define __BN_DEPRECATED_EXPAND(x) x
#define BN_DEPRECATED(...) __BN_DEPRECATED_EXPAND(__BN_DEPRECATED_GET_MACRO(__VA_ARGS__, __BN_DEPRECATED_WITH_REPLACEMENT, __BN_DEPRECATED_WITH_MESSAGE)(__VA_ARGS__))

// BN_IGNORE_WARNINGS_BEGIN(gcc_warning, msvc_num) / BN_IGNORE_WARNINGS_END
//
// Suppresses a specific warning within a block of code.
//
// gcc_warning: A GCC/Clang warning flag as a string, e.g. "-Wdeprecated-declarations"
// msvc_num: An MSVC warning number, e.g. 4996

#if defined(_MSC_VER)
#define BN_IGNORE_WARNINGS_BEGIN(gcc_warning, msvc_num) \
    __pragma(warning(push)) \
    __pragma(warning(disable: msvc_num))
#define BN_IGNORE_WARNINGS_END __pragma(warning(pop))
#elif defined(__clang__) || defined(__GNUC__)
#define __BN_PRAGMA(x) _Pragma(#x)
#define BN_IGNORE_WARNINGS_BEGIN(gcc_warning, msvc_num) \
    _Pragma("GCC diagnostic push") \
    __BN_PRAGMA(GCC diagnostic ignored gcc_warning)
#define BN_IGNORE_WARNINGS_END _Pragma("GCC diagnostic pop")
#else
#define BN_IGNORE_WARNINGS_BEGIN(gcc_warning, msvc_num)
#define BN_IGNORE_WARNINGS_END
#endif

// BN_IGNORE_DEPRECATION_WARNINGS_BEGIN / BN_IGNORE_DEPRECATION_WARNINGS_END
//
// Suppresses deprecation warnings within a block of code.

#define BN_IGNORE_DEPRECATION_WARNINGS_BEGIN BN_IGNORE_WARNINGS_BEGIN("-Wdeprecated-declarations", 4996)
#define BN_IGNORE_DEPRECATION_WARNINGS_END BN_IGNORE_WARNINGS_END

// BN_NO_UNIQUE_ADDRESS
//
// Allows a non-static data member of empty type to share storage with another
// member, removing the one-byte overhead the language otherwise requires. MSVC
// ignores the standard [[no_unique_address]] for ABI-compat reasons and
// provides [[msvc::no_unique_address]] instead.
#if defined(_MSC_VER)
#define BN_NO_UNIQUE_ADDRESS [[msvc::no_unique_address]]
#else
#define BN_NO_UNIQUE_ADDRESS [[no_unique_address]]
#endif

// BN_EMPTY_BASES
//
// Applied to a class definition to enable the empty base optimization across multiple
// empty base classes. Clang and GCC do this unconditionally, but MSVC only collapses a
// single empty base unless the class is annotated with __declspec(empty_bases). Without
// it, a class with several empty bases is padded larger than the sum of its data members.

#if defined(_MSC_VER)
#define BN_EMPTY_BASES __declspec(empty_bases)
#else
#define BN_EMPTY_BASES
#endif

// BN_NOINLINE
//
// Suppress inlining of a function at its call sites.

#if defined(_MSC_VER)
#define BN_NOINLINE __declspec(noinline)
#else
#define BN_NOINLINE __attribute__((noinline))
#endif
