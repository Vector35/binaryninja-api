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
// os_unfair_recursive_lock. With the MSVC STL, mutex wraps std::shared_mutex,
// which is a thin wrapper around SRWLOCK. Elsewhere, mutex uses an atomic-based
// implementation that blocks via platform_wait.
//
// Outside macOS, recursive_mutex is built on top of mutex.
//
// These are faster and significantly smaller than std::mutex /
// std::recursive_mutex.
//
// Note that `std::mutex` must still be used with `std::condition_variable` as
// `std::condition_variable` only works with `std::mutex`.

#include "base/assertions.h" // IWYU pragma: keep
#include "base/compiler.h" // IWYU pragma: keep

#ifdef __APPLE__

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
};

} // namespace bn::base

#else // Windows or Linux

#include "base/tsan.h"

#include <atomic>

#ifdef _MSC_VER
#include <shared_mutex>
#else
#include "base/platform_wait.h"
#endif

#ifdef _WIN32
#include <thread>
#else
#include <unistd.h>
#endif

namespace bn::base {

namespace detail {

#ifdef _WIN32

using ThreadId = std::thread::id;
inline ThreadId CurrentThreadID() noexcept
{
	static thread_local ThreadId tid = std::this_thread::get_id();
	return tid;
}

#else

// libstdc++'s std::thread::id is 8 bytes. Using it would force 8-byte alignment on recursive_mutex.
// pid_t is only 4 bytes, which decreases both the size and required alignment of recursive_mutex.
using ThreadId = pid_t;
inline ThreadId CurrentThreadID() noexcept
{
	static thread_local ThreadId tid = gettid();
	return tid;
}

#endif

} // namespace detail

#ifdef _MSC_VER

class mutex
{
	std::shared_mutex m_lock;

#if BN_ASSERTIONS_ENABLED
	std::atomic<detail::ThreadId> m_dbgOwner{detail::ThreadId{}};
#endif

public:
	mutex() = default;

	mutex(const mutex&) = delete;
	mutex& operator=(const mutex&) = delete;
	mutex(mutex&&) = delete;
	mutex& operator=(mutex&&) = delete;

	void lock() noexcept
	{
		BN_ASSERT(m_dbgOwner.load(std::memory_order_relaxed) != detail::CurrentThreadID()
			&& "deadlock: locking a mutex already held by this thread");
		m_lock.lock();
		BN_ASSERT(m_dbgOwner.exchange(detail::CurrentThreadID(), std::memory_order_relaxed) == detail::ThreadId{});
	}

	bool try_lock() noexcept
	{
		if (!m_lock.try_lock())
			return false;
		BN_ASSERT(m_dbgOwner.exchange(detail::CurrentThreadID(), std::memory_order_relaxed) == detail::ThreadId{});
		return true;
	}

	void unlock() noexcept
	{
		BN_ASSERT(m_dbgOwner.load(std::memory_order_relaxed) == detail::CurrentThreadID()
			&& "unlock called by non-owning thread");
		BN_ASSERT(m_dbgOwner.exchange(detail::ThreadId{}, std::memory_order_relaxed) != detail::ThreadId{});
		m_lock.unlock();
	}
};

#else

class mutex
{
	enum class State : int
	{
		Unlocked,
		Locked,
		Contended,
	};

	std::atomic<State> m_state{State::Unlocked};

#if BN_ASSERTIONS_ENABLED
	std::atomic<detail::ThreadId> m_dbgOwner{detail::ThreadId{}};
#endif

public:
	mutex() = default;

	mutex(const mutex&) = delete;
	mutex& operator=(const mutex&) = delete;
	mutex(mutex&&) = delete;
	mutex& operator=(mutex&&) = delete;

	void lock() noexcept
	{
		BN_ASSERT(m_dbgOwner.load(std::memory_order_relaxed) != detail::CurrentThreadID()
			&& "deadlock: locking a mutex already held by this thread");

		BN_TSAN_MUTEX_PRE_LOCK(this);
		auto expected = State::Unlocked;
		if (!m_state.compare_exchange_strong(expected, State::Locked,
				std::memory_order_acquire, std::memory_order_relaxed)) [[unlikely]]
			lock_slow(expected);
		BN_TSAN_MUTEX_POST_LOCK(this);

		BN_ASSERT(m_dbgOwner.exchange(detail::CurrentThreadID(), std::memory_order_relaxed) == detail::ThreadId{});
	}

	bool try_lock() noexcept
	{
		BN_TSAN_MUTEX_PRE_TRY_LOCK(this);
		auto expected = State::Unlocked;
		if (!m_state.compare_exchange_strong(expected, State::Locked,
				std::memory_order_acquire, std::memory_order_relaxed)) [[unlikely]]
		{
			BN_TSAN_MUTEX_POST_TRY_LOCK_FAILED(this);
			return false;
		}
		BN_TSAN_MUTEX_POST_TRY_LOCK(this);
		BN_ASSERT(m_dbgOwner.exchange(detail::CurrentThreadID(), std::memory_order_relaxed) == detail::ThreadId{});
		return true;
	}

	void unlock() noexcept
	{
		BN_ASSERT(m_dbgOwner.load(std::memory_order_relaxed) == detail::CurrentThreadID()
			&& "unlock called by non-owning thread");
		BN_ASSERT(m_dbgOwner.exchange(detail::ThreadId{}, std::memory_order_relaxed) != detail::ThreadId{});

		BN_TSAN_MUTEX_PRE_UNLOCK(this);
		if (m_state.exchange(State::Unlocked, std::memory_order_release) == State::Contended) [[unlikely]]
			detail::platform_notify_one(&m_state);
		BN_TSAN_MUTEX_POST_UNLOCK(this);
	}

private:
	BN_NOINLINE
	void lock_slow(State expected) noexcept
	{
		while (true)
		{
			// If the lock is held (not yet marked contended), exchange to mark it
			// contended and try to acquire in one step.
			if (expected != State::Contended)
				expected = m_state.exchange(State::Contended, std::memory_order_acquire);

			if (expected == State::Unlocked)
				return;

			detail::platform_wait(&m_state, State::Contended);
			expected = State::Locked;
		}
	}

};

#endif // _MSC_VER

class recursive_mutex
{
	mutex m_mutex;
	std::atomic<detail::ThreadId> m_owner{detail::ThreadId{}};
	int m_count{0};

public:
	recursive_mutex() = default;

	recursive_mutex(const recursive_mutex&) = delete;
	recursive_mutex& operator=(const recursive_mutex&) = delete;
	recursive_mutex(recursive_mutex&&) = delete;
	recursive_mutex& operator=(recursive_mutex&&) = delete;

	void lock() noexcept
	{
		auto me = detail::CurrentThreadID();
		if (m_owner.load(std::memory_order_relaxed) == me)
		{
			BN_TSAN_MUTEX_PRE_RECURSIVE_LOCK(this);
			++m_count;
			BN_TSAN_MUTEX_POST_RECURSIVE_LOCK(this);
			return;
		}
		m_mutex.lock();
		m_owner.store(me, std::memory_order_relaxed);
		m_count = 1;
	}

	bool try_lock() noexcept
	{
		auto me = detail::CurrentThreadID();
		if (m_owner.load(std::memory_order_relaxed) == me)
		{
			BN_TSAN_MUTEX_PRE_RECURSIVE_LOCK(this);
			++m_count;
			BN_TSAN_MUTEX_POST_RECURSIVE_LOCK(this);
			return true;
		}
		if (!m_mutex.try_lock())
			return false;
		m_owner.store(me, std::memory_order_relaxed);
		m_count = 1;
		return true;
	}

	void unlock() noexcept
	{
		BN_ASSERT(m_owner.load(std::memory_order_relaxed) == detail::CurrentThreadID()
			&& "unlock called by non-owning thread");
		BN_ASSERT(m_count > 0 && "unlock called on unheld recursive_mutex");
		if (--m_count > 0)
		{
			BN_TSAN_MUTEX_PRE_RECURSIVE_UNLOCK(this);
			BN_TSAN_MUTEX_POST_RECURSIVE_UNLOCK(this);
			return;
		}
		m_owner.store(detail::ThreadId{}, std::memory_order_relaxed);
		m_mutex.unlock();
	}
};

} // namespace bn::base

#endif
