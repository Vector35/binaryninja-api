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

// Mutex types that satisfy the C++ Lockable requirements.
//
// On macOS, mutex wraps os_unfair_lock and recursive_mutex wraps
// os_unfair_recursive_lock. These are faster and significantly smaller than
// std::mutex / std::recursive_mutex, which wrap the equivalent pthread mutexes.
//
// On other platforms, these are type aliases for the std equivalents.
//
// Note that `std::mutex` must still be used with `std::condition_variable` as
// `std::condition_variable` only works with `std::mutex`.

#include <optional>

#ifndef __APPLE__

#include <mutex>

namespace bn::base {

using mutex = std::mutex;
using recursive_mutex = std::recursive_mutex;

// Whether the calling thread holds the lock, where the platform can tell
inline std::optional<bool> held_by_current_thread(recursive_mutex&)
{
	return std::nullopt;
}

} // namespace bn::base

#else

#include <os/lock.h>

namespace bn::base {

class mutex
{
	os_unfair_lock m_lock = OS_UNFAIR_LOCK_INIT;

public:
	mutex() = default;

	mutex(const mutex&) = delete;
	mutex& operator=(const mutex&) = delete;
	mutex(mutex&&) = delete;
	mutex& operator=(mutex&&) = delete;

	void lock()
	{
		os_unfair_lock_lock(&m_lock);
	}

	bool try_lock()
	{
		return os_unfair_lock_trylock(&m_lock);
	}

	void unlock()
	{
		os_unfair_lock_unlock(&m_lock);
	}
};

// os_unfair_recursive_lock is private API. We provide our own declarations for it here.
// From https://github.com/apple-oss-distributions/libplatform/blob/libplatform-359.60.3/private/os/lock_private.h#L404-L463
namespace detail {

struct os_unfair_recursive_lock {
	os_unfair_lock ourl_lock;
	uint32_t ourl_count;
};

extern "C" {

OS_NOTHROW OS_NONNULL_ALL
void os_unfair_recursive_lock_lock_with_options(os_unfair_recursive_lock* lock,
		int options);

OS_NOTHROW OS_NONNULL_ALL
bool os_unfair_recursive_lock_trylock(os_unfair_recursive_lock* lock);

OS_NOTHROW OS_NONNULL_ALL
void os_unfair_recursive_lock_unlock(os_unfair_recursive_lock* lock);

OS_NOTHROW OS_NONNULL_ALL
bool os_unfair_recursive_lock_owned(os_unfair_recursive_lock* lock);

};

} // namespace bn::base::detail

class recursive_mutex
{
	detail::os_unfair_recursive_lock m_lock{OS_UNFAIR_LOCK_INIT, 0};

public:
	recursive_mutex() = default;

	recursive_mutex(const recursive_mutex&) = delete;
	recursive_mutex& operator=(const recursive_mutex&) = delete;
	recursive_mutex(recursive_mutex&&) = delete;
	recursive_mutex& operator=(recursive_mutex&&) = delete;

	void lock()
	{
		os_unfair_recursive_lock_lock_with_options(&m_lock, 0);
	}

	bool try_lock()
	{
		return os_unfair_recursive_lock_trylock(&m_lock);
	}

	void unlock()
	{
		os_unfair_recursive_lock_unlock(&m_lock);
	}

	// Whether the calling thread holds the lock
	bool owned()
	{
		return os_unfair_recursive_lock_owned(&m_lock);
	}
};

// Whether the calling thread holds the lock, where the platform can tell
inline std::optional<bool> held_by_current_thread(recursive_mutex& lock)
{
	return lock.owned();
}

} // namespace bn::base

#endif
