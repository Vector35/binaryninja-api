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

// Thread sanitizer detection and annotations

// BN_HAS_THREAD_SANITIZER
//
// Set to 1 when building with the thread sanitizer. GCC reports this through
// __SANITIZE_THREAD__ and Clang through __has_feature, and neither spelling
// covers both compilers.

#if defined(__SANITIZE_THREAD__)
#define BN_HAS_THREAD_SANITIZER 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define BN_HAS_THREAD_SANITIZER 1
#endif
#endif

#ifndef BN_HAS_THREAD_SANITIZER
#define BN_HAS_THREAD_SANITIZER 0
#endif

// BN_TSAN_ACQUIRE(addr) / BN_TSAN_RELEASE(addr)
//
// Describes a happens-before edge to the thread sanitizer for synchronization that it
// cannot observe, such as ordering established by a relaxed atomic load paired with an
// acquire fence. The thread that finishes with the data calls BN_TSAN_RELEASE, the thread
// that takes it over calls BN_TSAN_ACQUIRE with the same address. The edge is only
// reported once the release has actually run, so synchronization that fails to happen is
// still diagnosed. Both expand to nothing when the thread sanitizer is not in use.

#if BN_HAS_THREAD_SANITIZER
extern "C" void __tsan_acquire(void* addr);
extern "C" void __tsan_release(void* addr);
#define BN_TSAN_ACQUIRE(addr) __tsan_acquire((void*)(addr))
#define BN_TSAN_RELEASE(addr) __tsan_release((void*)(addr))
#else
#define BN_TSAN_ACQUIRE(addr) ((void)0)
#define BN_TSAN_RELEASE(addr) ((void)0)
#endif
