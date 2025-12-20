// Copyright (c) 2025 Vector 35 Inc
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

#include <atomic>
#include <memory>

namespace bn::base {

#ifdef __cpp_lib_atomic_shared_ptr

// Use the standard library implementation of `std::atomic<std::shared_ptr<T>>`.

template <typename T>
using atomic_shared_ptr = std::atomic<std::shared_ptr<T>>;

#else

// An implementation of `std::atomic<std::shared_ptr<T>>` in terms of free
// functions operating on `std::shared_ptr<T>`. Provided for compatibility with
// STL implementations such as libc++ that do not yet implement one.

template <typename T>
class atomic_shared_ptr
{
	std::shared_ptr<T> m_ptr;

public:
	using value_type = std::shared_ptr<T>;

	constexpr atomic_shared_ptr() noexcept = default;
	constexpr atomic_shared_ptr(std::nullptr_t) noexcept {}

	atomic_shared_ptr(std::shared_ptr<T> desired) noexcept
		: m_ptr(std::move(desired))
	{}

	atomic_shared_ptr(const atomic_shared_ptr&) = delete;
	atomic_shared_ptr& operator=(const atomic_shared_ptr&) = delete;

	void operator=(std::shared_ptr<T> desired) noexcept
	{
		store(std::move(desired));
	}

	void operator=(std::nullptr_t) noexcept
	{
		store(nullptr);
	}

	[[nodiscard]] std::shared_ptr<T> load(std::memory_order order = std::memory_order_seq_cst) const noexcept
	{
		return std::atomic_load_explicit(&m_ptr, order);
	}

	void store(std::shared_ptr<T> desired, std::memory_order order = std::memory_order_seq_cst) noexcept
	{
		std::atomic_store_explicit(&m_ptr, std::move(desired), order);
	}

	[[nodiscard]] std::shared_ptr<T> exchange(
		std::shared_ptr<T> desired,
		std::memory_order order = std::memory_order_seq_cst) noexcept
	{
		return std::atomic_exchange_explicit(&m_ptr, std::move(desired), order);
	}

	[[nodiscard]] bool compare_exchange_weak(
		std::shared_ptr<T>& expected,
		std::shared_ptr<T> desired,
		std::memory_order success,
		std::memory_order failure) noexcept
	{
		return std::atomic_compare_exchange_weak_explicit(&m_ptr, &expected, std::move(desired), success, failure);
	}

	[[nodiscard]] bool compare_exchange_weak(
		std::shared_ptr<T>& expected,
		std::shared_ptr<T> desired,
		std::memory_order order = std::memory_order_seq_cst) noexcept
	{
		return compare_exchange_weak(expected, std::move(desired), order, fail_order(order));
	}

	[[nodiscard]] bool compare_exchange_strong(
		std::shared_ptr<T>& expected,
		std::shared_ptr<T> desired,
		std::memory_order success,
		std::memory_order failure) noexcept
	{
		return std::atomic_compare_exchange_strong_explicit(&m_ptr, &expected, std::move(desired), success, failure);
	}

	[[nodiscard]] bool compare_exchange_strong(
		std::shared_ptr<T>& expected,
		std::shared_ptr<T> desired,
		std::memory_order order = std::memory_order_seq_cst) noexcept
	{
		return compare_exchange_strong(expected, std::move(desired), order, fail_order(order));
	}

	[[nodiscard]] operator std::shared_ptr<T>() const noexcept
	{
		return load();
	}

	static constexpr bool is_always_lock_free = false;

	[[nodiscard]] bool is_lock_free() const noexcept
	{
		return std::atomic_is_lock_free(&m_ptr);
	}

private:
	static constexpr std::memory_order fail_order(std::memory_order order) noexcept
	{
		switch (order)
		{
			case std::memory_order_acq_rel:
				return std::memory_order_acquire;
			case std::memory_order_release:
				return std::memory_order_relaxed;
			default:
				return order;
		}
	}
};

#endif

} // namespace bn::base

