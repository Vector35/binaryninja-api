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

// Assertion macros for internal consistency checks.
//
// There are two categories of assertions:
// 1) BN_ASSERT: These assertions can be enabled or disabled at compile time
//    using the BN_ASSERTIONS_ENABLED macro. They are intended for checking
//    conditions during development and debugging, but are compiled out of
//    production builds, either for performance reasons or because there is
//    a recovery path beyond trapping.
// 2) BN_RELEASE_ASSERT: These assertions are always enabled, regardless of
//    the BN_ASSERTIONS_ENABLED setting. They are intended for checking
//    conditions that must always hold true for the program to function
//    correctly, and indicate a serious error if they fail.
//
// By default, BN_ASSERTIONS_ENABLED is enabled in debug builds and disabled
// in release builds.

#ifndef BN_ASSERTIONS_ENABLED
#ifdef NDEBUG
#define BN_ASSERTIONS_ENABLED 0
#else
#define BN_ASSERTIONS_ENABLED 1
#endif
#endif

#ifdef _MSC_VER
#include <intrin.h>
#define BN_ASSERT_TRAP __fastfail(7 /* FAST_FAIL_FATAL_APP_EXIT */)
#else
#define BN_ASSERT_TRAP __builtin_trap()
#endif

// Forward-declare BNLogError so this header is self-contained, without
// pulling in all of binaryninjacore.h.
extern "C" void BNLogError(const char* fmt, ...);

#if BN_ASSERTIONS_ENABLED

// When assertions are enabled, reporting an assertion failure logs an error message then traps.
#define BN_REPORT_ASSERTION_FAILURE(message) \
	do \
	{ \
		BNLogError("Assertion failed: %s (%s:%d)", message, __FILE__, __LINE__); \
		BN_ASSERT_TRAP; \
	} while (0)

// BN_ASSERT checks the given condition and reports an assertion failure if the condition is false.
#define BN_ASSERT(condition) \
	do \
	{ \
		if (!(condition)) [[unlikely]] \
		{ \
			BN_REPORT_ASSERTION_FAILURE(#condition); \
		} \
	} while (0)

#else

// When assertions are disabled, reporting an assertion failure traps without logging.
// This is used for release assertions that are always enabled.
#define BN_REPORT_ASSERTION_FAILURE(message) BN_ASSERT_TRAP

// BN_ASSERT does nothing when assertions are disabled.
// Note that it does not evaluate the condition.
#define BN_ASSERT(condition) (void)0

#endif

// BN_RELEASE_ASSERT checks the given condition and reports an assertion failure
// if the condition is false.
// This assertion is always enabled, regardless of the BN_ASSERTIONS_ENABLED setting.
#define BN_RELEASE_ASSERT(condition) \
	do \
	{ \
		if (!(condition)) [[unlikely]] \
		{ \
			BN_REPORT_ASSERTION_FAILURE(#condition); \
		} \
	} while (0)

// Assert that this code path is not reached.
// This assertion is always enabled, regardless of the BN_ASSERTIONS_ENABLED setting.
#define BN_RELEASE_ASSERT_NOT_REACHED() \
	do \
	{ \
		BN_REPORT_ASSERTION_FAILURE("Unreachable code reached"); \
	} while (0)
