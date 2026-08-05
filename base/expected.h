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

// A value of type T or an error of type E, backporting C++23's std::expected. A function that can
// fail returns one of these instead of pairing an optional with an out-parameter.
//
// The special member functions are trivial whenever T and E make them trivial, so an expected of
// trivially copyable types is itself trivially copyable. This uses conditionally trivial special
// member functions (P0848), which requires GCC 10, Clang 16 or MSVC 19.28.
//
// Differences from std::expected, all of which can be filled in when something needs them:
//   - No in-place construction: no in_place_t / unexpect_t constructors, and no emplace().
//   - No conversion between different specializations, so an expected<U, G> does not convert to an
//     expected<T, E> even when U converts to T and G converts to E.
//   - No monadic operations: and_then(), or_else(), transform() and transform_error().
//   - No swap().

#include <exception>
#include <memory>
#include <new> // IWYU pragma: keep
#include <type_traits>
#include <utility>

namespace bn::base {

namespace detail {

// Replace the active member of a union. Destroy oldMember and construct newMember from args. If
// constructing throws, oldMember is restored, so the union is left holding what it held before.
template <class New, class Old, class... Args>
void ReplaceUnionMember(New* newMember, Old* oldMember, Args&&... args)
{
	if constexpr (std::is_nothrow_constructible_v<New, Args...>)
	{
		oldMember->~Old();
		::new (static_cast<void*>(newMember)) New(std::forward<Args>(args)...);
	}
	else if constexpr (std::is_nothrow_move_constructible_v<New>)
	{
		// Construct before destroying anything, so a throw here leaves the union untouched
		New created(std::forward<Args>(args)...);
		oldMember->~Old();
		::new (static_cast<void*>(newMember)) New(std::move(created));
	}
	else
	{
		static_assert(std::is_nothrow_move_constructible_v<Old>,
			"assigning across the value and error types of an expected requires one of them to be nothrow "
			"move constructible");

		Old saved(std::move(*oldMember));
		oldMember->~Old();
		try
		{
			::new (static_cast<void*>(newMember)) New(std::forward<Args>(args)...);
		}
		catch (...)
		{
			::new (static_cast<void*>(oldMember)) Old(std::move(saved));
			throw;
		}
	}
}


// Whether Type is a specialization of Template
template <class Type, template <class...> class Template>
constexpr bool IsSpecializationOf = false;

template <template <class...> class Template, class... Args>
constexpr bool IsSpecializationOf<Template<Args...>, Template> = true;

}  // namespace detail


// The error of an expected, used to disambiguate constructing one from its error type
template <class E>
class unexpected
{
	E m_error;

public:
	constexpr explicit unexpected(const E& error): m_error(error) {}
	constexpr explicit unexpected(E&& error): m_error(std::move(error)) {}

	[[nodiscard]] constexpr const E& error() const& { return m_error; }
	[[nodiscard]] constexpr E& error() & { return m_error; }
	[[nodiscard]] constexpr E&& error() && { return std::move(m_error); }
	[[nodiscard]] constexpr const E&& error() const&& { return std::move(m_error); }

	template <class E2>
	friend constexpr bool operator==(const unexpected& x, const unexpected<E2>& y)
	{
		return x.error() == y.error();
	}
};

template <class E>
unexpected(E) -> unexpected<E>;


// Thrown by expected::value() when the expected holds an error. Catching bad_expected_access<void>
// catches every specialization, whatever the error type is.
template <class E>
class bad_expected_access;

template <>
class bad_expected_access<void> : public std::exception
{
protected:
	bad_expected_access() noexcept = default;

public:
	const char* what() const noexcept override { return "bad access to bn::base::expected"; }
};

template <class E>
class bad_expected_access : public bad_expected_access<void>
{
	E m_error;

public:
	explicit bad_expected_access(E error): m_error(std::move(error)) {}

	[[nodiscard]] E& error() & noexcept { return m_error; }
	[[nodiscard]] const E& error() const& noexcept { return m_error; }
	[[nodiscard]] E&& error() && noexcept { return std::move(m_error); }
	[[nodiscard]] const E&& error() const&& noexcept { return std::move(m_error); }
};


template <class T, class E>
class expected
{
	static constexpr bool CopyConstructible = std::is_copy_constructible_v<T> && std::is_copy_constructible_v<E>;
	static constexpr bool MoveConstructible = std::is_move_constructible_v<T> && std::is_move_constructible_v<E>;
	// ReplaceUnionMember needs one of the two types to have a nothrow move to restore from
	static constexpr bool CanReplaceUnionMember =
		std::is_nothrow_move_constructible_v<T> || std::is_nothrow_move_constructible_v<E>;
	static constexpr bool CopyAssignable = CopyConstructible && CanReplaceUnionMember
		&& std::is_copy_assignable_v<T> && std::is_copy_assignable_v<E>;
	static constexpr bool MoveAssignable = MoveConstructible && CanReplaceUnionMember
		&& std::is_move_assignable_v<T> && std::is_move_assignable_v<E>;

	static constexpr bool TriviallyDestructible =
		std::is_trivially_destructible_v<T> && std::is_trivially_destructible_v<E>;
	static constexpr bool TriviallyCopyConstructible =
		std::is_trivially_copy_constructible_v<T> && std::is_trivially_copy_constructible_v<E>;
	static constexpr bool TriviallyMoveConstructible =
		std::is_trivially_move_constructible_v<T> && std::is_trivially_move_constructible_v<E>;
	static constexpr bool TriviallyCopyAssignable = CopyAssignable && TriviallyDestructible
		&& TriviallyCopyConstructible && std::is_trivially_copy_assignable_v<T>
		&& std::is_trivially_copy_assignable_v<E>;
	static constexpr bool TriviallyMoveAssignable = MoveAssignable && TriviallyDestructible
		&& TriviallyMoveConstructible && std::is_trivially_move_assignable_v<T>
		&& std::is_trivially_move_assignable_v<E>;

	// The move operations are declared only when both types can be moved, so that moving an expected
	// of an unmovable type falls back to the copy operations
	static constexpr bool NonTriviallyMoveConstructible = MoveConstructible && !TriviallyMoveConstructible;
	static constexpr bool NonTriviallyMoveAssignable = MoveAssignable && !TriviallyMoveAssignable;

	union
	{
		char m_empty;
		T m_value;
		E m_error;
	};
	bool m_hasValue;

	template <class Other>
	void Construct(Other&& other)
	{
		if (other.m_hasValue)
			::new (std::addressof(m_value)) T(std::forward<Other>(other).m_value);
		else
			::new (std::addressof(m_error)) E(std::forward<Other>(other).m_error);
		m_hasValue = other.m_hasValue;
	}

	template <class Other>
	void Assign(Other&& other)
	{
		if (m_hasValue && other.m_hasValue)
			m_value = std::forward<Other>(other).m_value;
		else if (!m_hasValue && !other.m_hasValue)
			m_error = std::forward<Other>(other).m_error;
		else if (other.m_hasValue)
		{
			detail::ReplaceUnionMember(
				std::addressof(m_value), std::addressof(m_error), std::forward<Other>(other).m_value);
			m_hasValue = true;
		}
		else
		{
			detail::ReplaceUnionMember(
				std::addressof(m_error), std::addressof(m_value), std::forward<Other>(other).m_error);
			m_hasValue = false;
		}
	}

public:
	using value_type = T;
	using error_type = E;

	constexpr expected()
		requires std::is_default_constructible_v<T>
	: m_value(), m_hasValue(true) {}

	template <class U = T>
		requires (std::is_constructible_v<T, U&&>
			&& !detail::IsSpecializationOf<std::remove_cvref_t<U>, expected>
			&& !detail::IsSpecializationOf<std::remove_cvref_t<U>, unexpected>)
	constexpr explicit(!std::is_convertible_v<U&&, T>) expected(U&& value):
		m_value(std::forward<U>(value)), m_hasValue(true)
	{}

	template <class G>
		requires std::is_constructible_v<E, const G&>
	constexpr explicit(!std::is_convertible_v<const G&, E>) expected(const unexpected<G>& error):
		m_error(error.error()), m_hasValue(false)
	{}

	template <class G>
		requires std::is_constructible_v<E, G>
	constexpr explicit(!std::is_convertible_v<G, E>) expected(unexpected<G>&& error):
		m_error(std::move(error).error()), m_hasValue(false)
	{}

	expected(const expected&) requires TriviallyCopyConstructible = default;
	expected(const expected&) requires (!CopyConstructible) = delete;
	expected(const expected& other): m_empty() { Construct(other); }

	expected(expected&&) requires TriviallyMoveConstructible = default;
	expected(expected&& other)
		noexcept(std::is_nothrow_move_constructible_v<T> && std::is_nothrow_move_constructible_v<E>)
		requires NonTriviallyMoveConstructible: m_empty()
	{
		Construct(std::move(other));
	}

	~expected() requires TriviallyDestructible = default;
	~expected()
	{
		if (m_hasValue)
			m_value.~T();
		else
			m_error.~E();
	}

	expected& operator=(const expected&) requires TriviallyCopyAssignable = default;
	expected& operator=(const expected&) requires (!CopyAssignable) = delete;
	expected& operator=(const expected& other)
	{
		if (this != std::addressof(other))
			Assign(other);

		return *this;
	}

	expected& operator=(expected&&) requires TriviallyMoveAssignable = default;
	expected& operator=(expected&& other)
		noexcept(std::is_nothrow_move_constructible_v<T>
			&& std::is_nothrow_move_assignable_v<T> && std::is_nothrow_move_constructible_v<E>
			&& std::is_nothrow_move_assignable_v<E>)
		requires NonTriviallyMoveAssignable
	{
		if (this != std::addressof(other))
			Assign(std::move(other));

		return *this;
	}

	[[nodiscard]] constexpr bool has_value() const noexcept { return m_hasValue; }
	constexpr explicit operator bool() const noexcept { return m_hasValue; }

	// The value, which must be present
	constexpr T& operator*() & noexcept { return m_value; }
	constexpr const T& operator*() const& noexcept { return m_value; }
	constexpr T&& operator*() && noexcept { return std::move(m_value); }
	constexpr const T&& operator*() const&& noexcept { return std::move(m_value); }
	constexpr T* operator->() noexcept { return std::addressof(m_value); }
	constexpr const T* operator->() const noexcept { return std::addressof(m_value); }

	// The value, throwing bad_expected_access if the expected holds an error instead
	[[nodiscard]] constexpr T& value() &
	{
		if (!m_hasValue)
			throw bad_expected_access<E>(m_error);

		return m_value;
	}

	[[nodiscard]] constexpr const T& value() const&
	{
		if (!m_hasValue)
			throw bad_expected_access<E>(m_error);

		return m_value;
	}

	[[nodiscard]] constexpr T&& value() &&
	{
		if (!m_hasValue)
			throw bad_expected_access<E>(std::move(m_error));

		return std::move(m_value);
	}

	[[nodiscard]] constexpr const T&& value() const&&
	{
		if (!m_hasValue)
			throw bad_expected_access<E>(m_error);

		return std::move(m_value);
	}

	// The error, which must be present
	[[nodiscard]] constexpr E& error() & noexcept { return m_error; }
	[[nodiscard]] constexpr const E& error() const& noexcept { return m_error; }
	[[nodiscard]] constexpr E&& error() && noexcept { return std::move(m_error); }
	[[nodiscard]] constexpr const E&& error() const&& noexcept { return std::move(m_error); }

	template <class U>
	[[nodiscard]] constexpr T value_or(U&& fallback) const&
	{
		return m_hasValue ? m_value : static_cast<T>(std::forward<U>(fallback));
	}

	template <class U>
	[[nodiscard]] constexpr T value_or(U&& fallback) &&
	{
		return m_hasValue ? std::move(m_value) : static_cast<T>(std::forward<U>(fallback));
	}

	// The error, or the fallback if the expected holds a value instead
	template <class G>
	[[nodiscard]] constexpr E error_or(G&& fallback) const&
	{
		return m_hasValue ? static_cast<E>(std::forward<G>(fallback)) : m_error;
	}

	template <class G>
	[[nodiscard]] constexpr E error_or(G&& fallback) &&
	{
		return m_hasValue ? static_cast<E>(std::forward<G>(fallback)) : std::move(m_error);
	}

	template <class T2, class E2>
	friend constexpr bool operator==(const expected& x, const expected<T2, E2>& y)
	{
		if (x.has_value() != y.has_value())
			return false;

		if (x.has_value())
			return *x == *y;

		return x.error() == y.error();
	}

	template <class T2>
		requires (!detail::IsSpecializationOf<T2, expected>)
	friend constexpr bool operator==(const expected& x, const T2& value)
	{
		return x.has_value() && *x == value;
	}

	template <class E2>
	friend constexpr bool operator==(const expected& x, const unexpected<E2>& error)
	{
		return !x.has_value() && x.error() == error.error();
	}
};


// An operation that either succeeds with no value or fails with an error
template <class E>
class expected<void, E>
{
	static constexpr bool CopyConstructible = std::is_copy_constructible_v<E>;
	static constexpr bool MoveConstructible = std::is_move_constructible_v<E>;
	static constexpr bool CopyAssignable = CopyConstructible && std::is_copy_assignable_v<E>;
	static constexpr bool MoveAssignable = MoveConstructible && std::is_move_assignable_v<E>;

	static constexpr bool TriviallyDestructible = std::is_trivially_destructible_v<E>;
	static constexpr bool TriviallyCopyConstructible = std::is_trivially_copy_constructible_v<E>;
	static constexpr bool TriviallyMoveConstructible = std::is_trivially_move_constructible_v<E>;
	static constexpr bool TriviallyCopyAssignable = CopyAssignable && TriviallyDestructible
		&& TriviallyCopyConstructible && std::is_trivially_copy_assignable_v<E>;
	static constexpr bool TriviallyMoveAssignable = MoveAssignable && TriviallyDestructible
		&& TriviallyMoveConstructible && std::is_trivially_move_assignable_v<E>;

	// The move operations are declared only when the error type can be moved, so that moving an
	// expected of an unmovable error type falls back to the copy operations
	static constexpr bool NonTriviallyMoveConstructible = MoveConstructible && !TriviallyMoveConstructible;
	static constexpr bool NonTriviallyMoveAssignable = MoveAssignable && !TriviallyMoveAssignable;

	union
	{
		char m_empty;
		E m_error;
	};
	bool m_hasValue;

	template <class Other>
	void Construct(Other&& other)
	{
		if (!other.m_hasValue)
			::new (std::addressof(m_error)) E(std::forward<Other>(other).m_error);
		m_hasValue = other.m_hasValue;
	}

	template <class Other>
	void Assign(Other&& other)
	{
		if (!m_hasValue && !other.m_hasValue)
			m_error = std::forward<Other>(other).m_error;
		else if (m_hasValue && !other.m_hasValue)
		{
			::new (std::addressof(m_error)) E(std::forward<Other>(other).m_error);
			m_hasValue = false;
		}
		else if (!m_hasValue)
		{
			m_error.~E();
			m_hasValue = true;
		}
	}

public:
	using value_type = void;
	using error_type = E;

	constexpr expected(): m_empty(), m_hasValue(true) {}

	template <class G>
		requires std::is_constructible_v<E, const G&>
	constexpr explicit(!std::is_convertible_v<const G&, E>) expected(const unexpected<G>& error):
		m_error(error.error()), m_hasValue(false)
	{}

	template <class G>
		requires std::is_constructible_v<E, G>
	constexpr explicit(!std::is_convertible_v<G, E>) expected(unexpected<G>&& error):
		m_error(std::move(error).error()), m_hasValue(false)
	{}

	expected(const expected&) requires TriviallyCopyConstructible = default;
	expected(const expected&) requires (!CopyConstructible) = delete;
	expected(const expected& other): m_empty() { Construct(other); }

	expected(expected&&) requires TriviallyMoveConstructible = default;
	expected(expected&& other)
		noexcept(std::is_nothrow_move_constructible_v<E>)
		requires NonTriviallyMoveConstructible: m_empty()
	{
		Construct(std::move(other));
	}

	~expected() requires TriviallyDestructible = default;
	~expected()
	{
		if (!m_hasValue)
			m_error.~E();
	}

	expected& operator=(const expected&) requires TriviallyCopyAssignable = default;
	expected& operator=(const expected&) requires (!CopyAssignable) = delete;
	expected& operator=(const expected& other)
	{
		if (this != std::addressof(other))
			Assign(other);

		return *this;
	}

	expected& operator=(expected&&) requires TriviallyMoveAssignable = default;
	expected& operator=(expected&& other)
		noexcept(std::is_nothrow_move_constructible_v<E> && std::is_nothrow_move_assignable_v<E>)
		requires NonTriviallyMoveAssignable
	{
		if (this != std::addressof(other))
			Assign(std::move(other));

		return *this;
	}

	[[nodiscard]] constexpr bool has_value() const noexcept { return m_hasValue; }
	constexpr explicit operator bool() const noexcept { return m_hasValue; }

	// Present only so that generic code can dereference any expected
	constexpr void operator*() const noexcept {}

	constexpr void value() const
	{
		if (!m_hasValue)
			throw bad_expected_access<E>(m_error);
	}

	[[nodiscard]] constexpr E& error() & noexcept { return m_error; }
	[[nodiscard]] constexpr const E& error() const& noexcept { return m_error; }
	[[nodiscard]] constexpr E&& error() && noexcept { return std::move(m_error); }
	[[nodiscard]] constexpr const E&& error() const&& noexcept { return std::move(m_error); }

	// The error, or the fallback if the expected succeeded instead
	template <class G>
	[[nodiscard]] constexpr E error_or(G&& fallback) const&
	{
		return m_hasValue ? static_cast<E>(std::forward<G>(fallback)) : m_error;
	}

	template <class G>
	[[nodiscard]] constexpr E error_or(G&& fallback) &&
	{
		return m_hasValue ? static_cast<E>(std::forward<G>(fallback)) : std::move(m_error);
	}

	template <class E2>
	friend constexpr bool operator==(const expected& x, const expected<void, E2>& y)
	{
		if (x.has_value() != y.has_value())
			return false;

		return x.has_value() || x.error() == y.error();
	}

	template <class E2>
	friend constexpr bool operator==(const expected& x, const unexpected<E2>& error)
	{
		return !x.has_value() && x.error() == error.error();
	}
};

}  // namespace bn::base
