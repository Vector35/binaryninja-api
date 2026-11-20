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

// Platform-native address-based wait/wake primitives.
//
// On Linux, wraps futex(). On macOS, wraps __ulock_wait/__ulock_wake.
// On Windows, wraps WaitOnAddress/WakeByAddress*.
//
// These bypass the C++ standard library's std::atomic::wait/notify, which
// adds spin/backoff overhead and (on some platforms) routes through a shared
// contention table instead of waiting directly on the user's address.

#include <atomic>
#include <cstdint>

#ifdef __linux__

#include <climits>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace bn::base::detail {

template<typename T>
inline void platform_wait(std::atomic<T>* addr, T expected) noexcept
{
	static_assert(sizeof(T) == 4, "Linux futex requires 4-byte values");
	syscall(SYS_futex, addr, FUTEX_WAIT_PRIVATE, static_cast<int>(expected),
		nullptr, nullptr, 0);
}

template<typename T>
inline void platform_notify_one(std::atomic<T>* addr) noexcept
{
	static_assert(sizeof(T) == 4);
	syscall(SYS_futex, addr, FUTEX_WAKE_PRIVATE, 1, nullptr, nullptr, 0);
}

template<typename T>
inline void platform_notify_all(std::atomic<T>* addr) noexcept
{
	static_assert(sizeof(T) == 4);
	syscall(SYS_futex, addr, FUTEX_WAKE_PRIVATE, INT_MAX, nullptr, nullptr, 0);
}

} // namespace bn::base::detail

#elif defined(__APPLE__)

namespace bn::base::detail {

// From xnu/bsd/sys/ulock.h (private API, stable ABI).
constexpr uint32_t kULockCompareAndWait = 1;
constexpr uint32_t kULockCompareAndWait64 = 5;
constexpr uint32_t kULockWakeAll = 0x00000100;

extern "C" int __ulock_wait(uint32_t operation, void* addr, uint64_t value,
	uint32_t timeout);
extern "C" int __ulock_wake(uint32_t operation, void* addr,
	uint64_t wake_value);

template<typename T>
inline void platform_wait(std::atomic<T>* addr, T expected) noexcept
{
	static_assert(sizeof(T) == 4 || sizeof(T) == 8,
		"macOS __ulock requires 4- or 8-byte values");
	if constexpr (sizeof(T) == 4)
		__ulock_wait(kULockCompareAndWait, addr,
			static_cast<uint64_t>(static_cast<uint32_t>(expected)), 0);
	else
		__ulock_wait(kULockCompareAndWait64, addr,
			static_cast<uint64_t>(expected), 0);
}

template<typename T>
inline void platform_notify_one(std::atomic<T>* addr) noexcept
{
	static_assert(sizeof(T) == 4 || sizeof(T) == 8);
	if constexpr (sizeof(T) == 4)
		__ulock_wake(kULockCompareAndWait, addr, 0);
	else
		__ulock_wake(kULockCompareAndWait64, addr, 0);
}

template<typename T>
inline void platform_notify_all(std::atomic<T>* addr) noexcept
{
	static_assert(sizeof(T) == 4 || sizeof(T) == 8);
	if constexpr (sizeof(T) == 4)
		__ulock_wake(kULockCompareAndWait | kULockWakeAll, addr, 0);
	else
		__ulock_wake(kULockCompareAndWait64 | kULockWakeAll, addr, 0);
}

} // namespace bn::base::detail

#elif defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace bn::base::detail {

template<typename T>
inline void platform_wait(std::atomic<T>* addr, T expected) noexcept
{
	static_assert(sizeof(T) <= 8, "WaitOnAddress supports values up to 8 bytes");
	WaitOnAddress(addr, &expected, sizeof(T), INFINITE);
}

template<typename T>
inline void platform_notify_one(std::atomic<T>* addr) noexcept
{
	WakeByAddressSingle(addr);
}

template<typename T>
inline void platform_notify_all(std::atomic<T>* addr) noexcept
{
	WakeByAddressAll(addr);
}

} // namespace bn::base::detail

#endif
