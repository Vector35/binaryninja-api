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

// A compact reader/writer mutex implementation
//
// Satisfies the C++ SharedLockable requirements so is usable with
// std::shared_lock / std::unique_lock.
//
// With the MSVC STL, aliases std::shared_mutex, which is a thin wrapper around
// SRWLOCK. Elsewhere, uses a custom atomic-based implementation that prefers
// writers: a waiting writer stops new readers from entering and acquires once
// the active readers have completed, so a steady stream of readers cannot
// starve it.

#include "base/compiler.h"

#ifdef _MSC_VER

#include <shared_mutex>

namespace bn::base {

using shared_mutex = std::shared_mutex;

} // namespace bn::base

#else

#include <atomic>
#include <stdint.h>

#include "base/platform_wait.h"
#include "base/tsan.h"

namespace bn::base {

class shared_mutex
{
	// m_state bit layout:
	// - bit 31: WriterActive (exclusive owner present)
	// - bit 30: Contended (sticky hint that waiters may exist while state != 0)
	// - bit 29: WriterPending (one or more writers are waiting)
	// - bits 0..28: reader count
	//
	// Ownership invariant:
	// - WriterActive and reader count are mutually exclusive owners.
	// - No owners means (m_state & OwnerMask) == 0.
	// - While WriterPending is set, new readers do not enter.
	//
	// Wait/wake protocol:
	// - Waiters block on the exact m_state value via platform_wait.
	// - Contended is set before waiting and used by unlock paths to decide
	//   whether to issue wake_all.
	// - Writers set WriterPending while queued to gate new readers.
	// - A successful writer acquisition clears WriterPending, opening the gate.
	// - The last reader out clears Contended when nothing else is pending, so a
	//   stale hint costs at most one redundant wake_all per contention episode.
	//   It stays set while a writer is queued and that writer's unlock clears it.
	//
	// Memory ordering:
	// - Successful lock acquisitions use acquire semantics.
	// - Unlock paths use release semantics.
	// - Contended-bit updates are relaxed because they coordinate wake behavior,
	//   not protected data visibility.
	std::atomic<uint32_t> m_state{0};

	static constexpr uint32_t WriterActive = uint32_t{1} << 31;
	static constexpr uint32_t Contended = uint32_t{1} << 30;
	static constexpr uint32_t WriterPending = uint32_t{1} << 29;
	static constexpr uint32_t ReaderMask = WriterPending - 1;
	static constexpr uint32_t OwnerMask = WriterActive | ReaderMask;

	static constexpr bool ReaderCanAcquire(uint32_t state) noexcept
	{
		return (state & (WriterActive | WriterPending)) == 0;
	}

	static constexpr bool WriterCanAcquire(uint32_t state) noexcept
	{
		return (state & OwnerMask) == 0;
	}

	static constexpr uint32_t ReaderAcquireState(uint32_t state) noexcept
	{
		return state + 1;
	}

	static constexpr uint32_t WriterAcquireState(uint32_t state) noexcept
	{
		// Once a writer acquires ownership, clear the reader gate so readers may
		// resume after this writer releases.
		return (state | WriterActive) & ~WriterPending;
	}

	static constexpr uint32_t ReaderWaitBits(uint32_t state) noexcept
	{
		return (state & Contended) ? 0 : Contended;
	}

	static constexpr uint32_t WriterWaitBits(uint32_t state) noexcept
	{
		uint32_t bits = 0;
		if (!(state & Contended))
			bits |= Contended;
		if (!(state & WriterPending))
			bits |= WriterPending;
		return bits;
	}

	static constexpr bool LastReaderExiting(uint32_t previousState) noexcept
	{
		return (previousState & ReaderMask) == 1;
	}

public:
	shared_mutex() = default;

	shared_mutex(const shared_mutex&) = delete;
	shared_mutex& operator=(const shared_mutex&) = delete;
	shared_mutex(shared_mutex&&) = delete;
	shared_mutex& operator=(shared_mutex&&) = delete;

	void lock_shared() noexcept
	{
		BN_TSAN_MUTEX_PRE_LOCK_SHARED(this);
		uint32_t state = m_state.load(std::memory_order_relaxed);
		if (ReaderCanAcquire(state)) [[likely]]
		{
			if (m_state.compare_exchange_weak(state, ReaderAcquireState(state),
						std::memory_order_acquire, std::memory_order_relaxed)) [[likely]]
			{
				BN_TSAN_MUTEX_POST_LOCK_SHARED(this);
				return;
			}
		}

		lock_shared_slow(state);
		BN_TSAN_MUTEX_POST_LOCK_SHARED(this);
	}

	bool try_lock_shared() noexcept
	{
		BN_TSAN_MUTEX_PRE_TRY_LOCK_SHARED(this);
		uint32_t state = m_state.load(std::memory_order_relaxed);
		while (true)
		{
			if (!ReaderCanAcquire(state)) [[unlikely]]
			{
				BN_TSAN_MUTEX_POST_TRY_LOCK_SHARED_FAILED(this);
				return false;
			}
			if (m_state.compare_exchange_weak(state, ReaderAcquireState(state),
						std::memory_order_acquire, std::memory_order_relaxed)) [[likely]]
			{
				BN_TSAN_MUTEX_POST_TRY_LOCK_SHARED(this);
				return true;
			}
		}
	}

	void unlock_shared() noexcept
	{
		BN_TSAN_MUTEX_PRE_UNLOCK_SHARED(this);
		uint32_t prev = m_state.fetch_sub(1, std::memory_order_release);
		if (LastReaderExiting(prev) && (prev & Contended)) [[unlikely]]
		{
			// Drop the contention hint once nothing is left to wait for, otherwise every
			// last reader out keeps waking until a writer clears it. A waiter that sets
			// the hint again concurrently makes the exchange fail and keeps it.
			uint32_t idle = Contended;
			m_state.compare_exchange_strong(idle, 0, std::memory_order_relaxed, std::memory_order_relaxed);
			detail::platform_notify_all(&m_state);
		}
		BN_TSAN_MUTEX_POST_UNLOCK_SHARED(this);
	}

	void lock() noexcept
	{
		BN_TSAN_MUTEX_PRE_LOCK(this);
		uint32_t state = m_state.load(std::memory_order_relaxed);
		if (WriterCanAcquire(state)) [[likely]]
		{
			if (m_state.compare_exchange_weak(state, WriterAcquireState(state),
						std::memory_order_acquire, std::memory_order_relaxed)) [[likely]]
			{
				BN_TSAN_MUTEX_POST_LOCK(this);
				return;
			}
		}

		lock_slow(state);
		BN_TSAN_MUTEX_POST_LOCK(this);
	}

	bool try_lock() noexcept
	{
		BN_TSAN_MUTEX_PRE_TRY_LOCK(this);
		uint32_t state = m_state.load(std::memory_order_relaxed);
		while (true)
		{
			if (!WriterCanAcquire(state)) [[unlikely]]
			{
				BN_TSAN_MUTEX_POST_TRY_LOCK_FAILED(this);
				return false;
			}

			if (m_state.compare_exchange_weak(state, WriterAcquireState(state),
						std::memory_order_acquire, std::memory_order_relaxed)) [[likely]]
			{
				BN_TSAN_MUTEX_POST_TRY_LOCK(this);
				return true;
			}
		}
	}

	void unlock() noexcept
	{
		BN_TSAN_MUTEX_PRE_UNLOCK(this);
		uint32_t prev = m_state.exchange(0, std::memory_order_release);
		if (prev & Contended) [[unlikely]]
			detail::platform_notify_all(&m_state);
		BN_TSAN_MUTEX_POST_UNLOCK(this);
	}

private:
	// The acquisition loops live out of line so that the uncontended fast paths stay small enough to
	// inline into their callers. Both take the state read by the failed fast-path attempt.
	BN_NOINLINE
	void lock_shared_slow(uint32_t state) noexcept
	{
		while (true)
		{
			if (ReaderCanAcquire(state))
			{
				if (m_state.compare_exchange_weak(state, ReaderAcquireState(state),
							std::memory_order_acquire, std::memory_order_relaxed))
					return;
			}
			else
			{
				if (uint32_t waitBits = ReaderWaitBits(state))
				{
					if (m_state.compare_exchange_weak(state, state | waitBits,
								std::memory_order_relaxed, std::memory_order_relaxed))
						state |= waitBits;
					continue;
				}

				detail::platform_wait(&m_state, state);
				state = m_state.load(std::memory_order_relaxed);
			}
		}
	}

	BN_NOINLINE
	void lock_slow(uint32_t state) noexcept
	{
		while (true)
		{
			if (WriterCanAcquire(state))
			{
				if (m_state.compare_exchange_weak(state, WriterAcquireState(state),
							std::memory_order_acquire, std::memory_order_relaxed))
					return;
			}
			else
			{
				if (uint32_t waitBits = WriterWaitBits(state))
				{
					if (m_state.compare_exchange_weak(state, state | waitBits,
								std::memory_order_relaxed, std::memory_order_relaxed))
						state |= waitBits;
					continue;
				}

				detail::platform_wait(&m_state, state);
				state = m_state.load(std::memory_order_relaxed);
			}
		}
	}
};

} // namespace bn::base

#endif
