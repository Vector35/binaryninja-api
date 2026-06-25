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

#include <compare>  // IWYU pragma: keep
#include <stddef.h>
#include <functional>
#include <type_traits>
#include <utility>

#include <fmt/base.h>

#include "base/compiler.h"

// StrongTypedef gives a primitive type a distinct identity so that values which
// happen to share an underlying representation (addresses, offsets, indices,
// sizes, ...) cannot be interchanged by accident.
//
//   using Address = bn::base::StrongTypedef<uint64_t, struct AddressTag>;
//
// An Address is not implicitly convertible to or from uint64_t. The conversion must be
// spelled explicitly, with static_cast or the Value() accessor. The Tag type is a phantom
// parameter. It need never be a complete type and serves only to distinguish two
// StrongTypedefs over the same underlying type.
//
// Operations are opt-in through modifiers listed after the tag:
//
//   namespace st = ::bn::base::strong_typedef;
//   using AddressOffset = bn::base::StrongTypedef<int64_t, struct AddressOffsetTag,
//                             st::Arithmetic, st::Ordered>;
//   using Address = bn::base::StrongTypedef<uint64_t, struct AddressTag,
//                       st::Affine<AddressOffset>, st::Ordered, st::Hashable>;
//
// Unless noted otherwise, the operators a modifier adds are homogeneous: both operands are
// the StrongTypedef and the result is the StrongTypedef, never the underlying type. The
// modifiers, all in namespace bn::base::strong_typedef:
//
//   Comparison
//     Equality        a == b, a != b
//     Ordered         a <=> b and the relational operators, plus Equality
//
//   Arithmetic
//     Addable         a + b, a += b
//     Subtractable    a - b, a -= b
//     Multipliable    a * b, a *= b
//     Divisible       a / b, a /= b
//     Modulo          a % b, a %= b
//     Negatable       -a
//     Incrementable   ++a, a++
//     Decrementable   --a, a--
//     Arithmetic      every modifier in this group, for group-like values such as an
//                     offset or a count where adding two of them is meaningful
//
//   Bitwise
//     BitAnd          a & b, a &= b
//     BitOr           a | b, a |= b
//     BitXor          a ^ b, a ^= b
//     BitNot          ~a
//     Shiftable       a << n, a >> n, a <<= n, a >>= n, where n is an int
//     Bitwise         every modifier in this group
//
//   Points and offsets
//     Affine<Diff>    a - b yields Diff, and a + d, d + a, a - d, a += d, a -= d carry a
//                     point-like value such as an address by an offset of the existing
//                     type Diff. Adding two points is intentionally not provided.
//     AffinePoint     Affine over a difference type it synthesizes rather than one named
//                     by the caller, exposed as Self::Offset. Underlying type must be
//                     integral.
//
//   Other
//     Hashable        usable as a key in std and absl hash containers
//     Formattable     formattable with fmt, forwarding format specs such as {:#x} to the
//                     underlying type's formatter
//     NonExtractable  removes the explicit operator T() and the Value() accessor, so the
//                     underlying value can be constructed but never read back out. Every
//                     other modifier continues to function as normal.
//
// Each modifier is a type with a nested `template <typename Self, typename T> struct
// Apply` mixin. StrongTypedef inherits from every modifier's Apply. Each Apply defines
// the operators it adds as hidden friends written in terms of the stored value.
//
// Each Apply has a requires clause naming a Supports... concept that the underlying type
// must satisfy. Applying a modifier to an underlying type that lacks its operations
// therefore fails at the StrongTypedef declaration, with a diagnostic that names the
// unmet concept, instead of at a later use site.

namespace bn::base {

namespace strong_typedef {

template <typename T, typename Tag, typename... Mods>
class StrongTypedef;

namespace detail {

// True when Modifier appears in the Mods pack.
template <typename Modifier, typename... Mods>
inline constexpr bool HasModifier = (std::is_same_v<Modifier, Mods> || ...);

// Internal access to a StrongTypedef's underlying value so that modifiers have
// access to it even when NonExtractable is in use.
struct Access
{
	template <typename Self>
	static constexpr decltype(auto) Get(Self&& self) noexcept { return (std::forward<Self>(self).m_value); }
};

// Concepts describing what an underlying type must support for a given modifier.
template <typename T> concept SupportsAdd = requires(T a, T b) { a + b; a += b; };
template <typename T> concept SupportsSubtract = requires(T a, T b) { a - b; a -= b; };
template <typename T> concept SupportsMultiply = requires(T a, T b) { a * b; a *= b; };
template <typename T> concept SupportsDivide = requires(T a, T b) { a / b; a /= b; };
template <typename T> concept SupportsModulo = requires(T a, T b) { a % b; a %= b; };
template <typename T> concept SupportsNegate = requires(T a) { -a; };
template <typename T> concept SupportsIncrement = requires(T a) { ++a; a++; };
template <typename T> concept SupportsDecrement = requires(T a) { --a; a--; };
template <typename T> concept SupportsBitAnd = requires(T a, T b) { a & b; a &= b; };
template <typename T> concept SupportsBitOr = requires(T a, T b) { a | b; a |= b; };
template <typename T> concept SupportsBitXor = requires(T a, T b) { a ^ b; a ^= b; };
template <typename T> concept SupportsBitNot = requires(T a) { ~a; };
template <typename T> concept SupportsShift = requires(T a) { a << 1; a >> 1; };
template <typename T> concept SupportsEquality = requires(T a, T b) { a == b; };
template <typename T> concept SupportsOrdering = requires(T a, T b) { a <=> b; };

// Operators relating a point type Self to its difference type Diff.
template <typename Self, typename Diff>
struct AffineOps
{
	friend constexpr Diff operator-(const Self& a, const Self& b) { return Diff(detail::Access::Get(a) - detail::Access::Get(b)); }
	friend constexpr Self operator+(const Self& a, const Diff& d) { return Self(detail::Access::Get(a) + detail::Access::Get(d)); }
	friend constexpr Self operator+(const Diff& d, const Self& a) { return Self(detail::Access::Get(d) + detail::Access::Get(a)); }
	friend constexpr Self operator-(const Self& a, const Diff& d) { return Self(detail::Access::Get(a) - detail::Access::Get(d)); }
	friend constexpr Self& operator+=(Self& a, const Diff& d) { detail::Access::Get(a) += detail::Access::Get(d); return a; }
	friend constexpr Self& operator-=(Self& a, const Diff& d) { detail::Access::Get(a) -= detail::Access::Get(d); return a; }
};

} // namespace detail


// Permits == and !=. The compiler synthesizes != from the defined ==.
struct Equality
{
	template <typename Self, typename T>
		requires detail::SupportsEquality<T>
	struct Apply
	{
		friend constexpr bool operator==(const Self& a, const Self& b) { return detail::Access::Get(a) == detail::Access::Get(b); }
	};
};

// Permits the relational operators via operator<=>. Also includes Equality, because a
// user-provided operator<=> does not by itself make == available.
struct Ordered
{
	template <typename Self, typename T>
		requires detail::SupportsOrdering<T>
	struct Apply : Equality::Apply<Self, T>
	{
		friend constexpr auto operator<=>(const Self& a, const Self& b) { return detail::Access::Get(a) <=> detail::Access::Get(b); }
	};
};

struct Addable
{
	template <typename Self, typename T>
		requires detail::SupportsAdd<T>
	struct Apply
	{
		friend constexpr Self operator+(const Self& a, const Self& b) { return Self(detail::Access::Get(a) + detail::Access::Get(b)); }
		friend constexpr Self& operator+=(Self& a, const Self& b) { detail::Access::Get(a) += detail::Access::Get(b); return a; }
	};
};

struct Subtractable
{
	template <typename Self, typename T>
		requires detail::SupportsSubtract<T>
	struct Apply
	{
		friend constexpr Self operator-(const Self& a, const Self& b) { return Self(detail::Access::Get(a) - detail::Access::Get(b)); }
		friend constexpr Self& operator-=(Self& a, const Self& b) { detail::Access::Get(a) -= detail::Access::Get(b); return a; }
	};
};

struct Multipliable
{
	template <typename Self, typename T>
		requires detail::SupportsMultiply<T>
	struct Apply
	{
		friend constexpr Self operator*(const Self& a, const Self& b) { return Self(detail::Access::Get(a) * detail::Access::Get(b)); }
		friend constexpr Self& operator*=(Self& a, const Self& b) { detail::Access::Get(a) *= detail::Access::Get(b); return a; }
	};
};

struct Divisible
{
	template <typename Self, typename T>
		requires detail::SupportsDivide<T>
	struct Apply
	{
		friend constexpr Self operator/(const Self& a, const Self& b) { return Self(detail::Access::Get(a) / detail::Access::Get(b)); }
		friend constexpr Self& operator/=(Self& a, const Self& b) { detail::Access::Get(a) /= detail::Access::Get(b); return a; }
	};
};

struct Modulo
{
	template <typename Self, typename T>
		requires detail::SupportsModulo<T>
	struct Apply
	{
		friend constexpr Self operator%(const Self& a, const Self& b) { return Self(detail::Access::Get(a) % detail::Access::Get(b)); }
		friend constexpr Self& operator%=(Self& a, const Self& b) { detail::Access::Get(a) %= detail::Access::Get(b); return a; }
	};
};

struct Negatable
{
	template <typename Self, typename T>
		requires detail::SupportsNegate<T>
	struct Apply
	{
		friend constexpr Self operator-(const Self& a) { return Self(-detail::Access::Get(a)); }
	};
};

struct Incrementable
{
	template <typename Self, typename T>
		requires detail::SupportsIncrement<T>
	struct Apply
	{
		friend constexpr Self& operator++(Self& a) { ++detail::Access::Get(a); return a; }
		friend constexpr Self operator++(Self& a, int) { Self tmp = a; ++detail::Access::Get(a); return tmp; }
	};
};

struct Decrementable
{
	template <typename Self, typename T>
		requires detail::SupportsDecrement<T>
	struct Apply
	{
		friend constexpr Self& operator--(Self& a) { --detail::Access::Get(a); return a; }
		friend constexpr Self operator--(Self& a, int) { Self tmp = a; --detail::Access::Get(a); return tmp; }
	};
};

// Homogeneous arithmetic (Self op Self -> Self) for group-like types such as an offset
// or a count. Point-like types such as an address should use Affine instead.
struct Arithmetic
{
	template <typename Self, typename T>
	struct Apply
		: Addable::Apply<Self, T>, Subtractable::Apply<Self, T>, Multipliable::Apply<Self, T>,
		  Divisible::Apply<Self, T>, Modulo::Apply<Self, T>, Negatable::Apply<Self, T>,
		  Incrementable::Apply<Self, T>, Decrementable::Apply<Self, T>
	{
	};
};

struct BitAnd
{
	template <typename Self, typename T>
		requires detail::SupportsBitAnd<T>
	struct Apply
	{
		friend constexpr Self operator&(const Self& a, const Self& b) { return Self(detail::Access::Get(a) & detail::Access::Get(b)); }
		friend constexpr Self& operator&=(Self& a, const Self& b) { detail::Access::Get(a) &= detail::Access::Get(b); return a; }
	};
};

struct BitOr
{
	template <typename Self, typename T>
		requires detail::SupportsBitOr<T>
	struct Apply
	{
		friend constexpr Self operator|(const Self& a, const Self& b) { return Self(detail::Access::Get(a) | detail::Access::Get(b)); }
		friend constexpr Self& operator|=(Self& a, const Self& b) { detail::Access::Get(a) |= detail::Access::Get(b); return a; }
	};
};

struct BitXor
{
	template <typename Self, typename T>
		requires detail::SupportsBitXor<T>
	struct Apply
	{
		friend constexpr Self operator^(const Self& a, const Self& b) { return Self(detail::Access::Get(a) ^ detail::Access::Get(b)); }
		friend constexpr Self& operator^=(Self& a, const Self& b) { detail::Access::Get(a) ^= detail::Access::Get(b); return a; }
	};
};

struct BitNot
{
	template <typename Self, typename T>
		requires detail::SupportsBitNot<T>
	struct Apply
	{
		friend constexpr Self operator~(const Self& a) { return Self(~detail::Access::Get(a)); }
	};
};

struct Shiftable
{
	template <typename Self, typename T>
		requires detail::SupportsShift<T>
	struct Apply
	{
		friend constexpr Self operator<<(const Self& a, int n) { return Self(detail::Access::Get(a) << n); }
		friend constexpr Self operator>>(const Self& a, int n) { return Self(detail::Access::Get(a) >> n); }
		friend constexpr Self& operator<<=(Self& a, int n) { detail::Access::Get(a) <<= n; return a; }
		friend constexpr Self& operator>>=(Self& a, int n) { detail::Access::Get(a) >>= n; return a; }
	};
};

struct Bitwise
{
	template <typename Self, typename T>
	struct Apply
		: BitAnd::Apply<Self, T>, BitOr::Apply<Self, T>, BitXor::Apply<Self, T>,
		  BitNot::Apply<Self, T>, Shiftable::Apply<Self, T>
	{
	};
};

// Affine relationship with a separate difference type Diff:
//   Self  - Self -> Diff   (the distance between two points)
//   Self  + Diff -> Self   (step a point by a distance)
//   Diff  + Self -> Self
//   Self  - Diff -> Self
// Adding two points (Self + Self) is intentionally not provided.
template <typename Diff>
struct Affine
{
	template <typename Self, typename T>
		requires detail::SupportsAdd<T> && detail::SupportsSubtract<T>
	struct Apply : detail::AffineOps<Self, Diff>
	{
	};
};

namespace detail {

template <typename Self, typename T>
struct SynthOffsetTag {};

// The difference type synthesized by AffinePoint. It is a signed group-arithmetic type
// with a tag unique to the point type Self.
template <typename Self, typename T>
using SynthOffset = StrongTypedef<std::make_signed_t<T>, SynthOffsetTag<Self, T>, Arithmetic, Ordered>;

} // namespace detail

// Like Affine, but synthesizes the difference type and exposes it as Self::Offset, so one
// declaration provides both the affine operators and a named offset type. Requires an
// integral underlying type.
struct AffinePoint
{
	template <typename Self, typename T>
		requires std::is_integral_v<T>
	struct Apply : detail::AffineOps<Self, detail::SynthOffset<Self, T>>
	{
		using Offset = detail::SynthOffset<Self, T>;
	};
};

// Makes the type usable as a key in both std and absl hash containers. Enables a
// constrained std::hash specialization and provides an AbslHashValue overload.
struct Hashable
{
	template <typename Self, typename T>
	struct Apply
	{
		template <typename H>
		friend H AbslHashValue(H state, const Self& v)
		{
			return H::combine(std::move(state), detail::Access::Get(v));
		}
	};
};

// Marker that enables the StrongTypedef fmt::formatter. Carries no operators.
struct Formattable
{
	template <typename Self, typename T>
	struct Apply
	{
	};
};

// Disable both the explicit operator T() and the Value() accessor.
// All other modifiers continue to function as normal.
struct NonExtractable
{
	template <typename Self, typename T>
	struct Apply
	{
	};
};

template <typename T, typename Tag, typename... Mods>
class BN_EMPTY_BASES StrongTypedef : public Mods::template Apply<StrongTypedef<T, Tag, Mods...>, T>...
{
public:
	using UnderlyingType = T;

	constexpr StrongTypedef() = default;

	explicit constexpr StrongTypedef(const T& value) noexcept(std::is_nothrow_copy_constructible_v<T>)
		: m_value(value)
	{
	}

	explicit constexpr StrongTypedef(T&& value) noexcept(std::is_nothrow_move_constructible_v<T>)
		: m_value(std::move(value))
	{
	}

	explicit constexpr operator T() const noexcept(std::is_nothrow_copy_constructible_v<T>)
		requires (!detail::HasModifier<NonExtractable, Mods...>)
	{
		return m_value;
	}

	constexpr T& Value() & noexcept
		requires (!detail::HasModifier<NonExtractable, Mods...>) { return m_value; }
	constexpr const T& Value() const& noexcept
		requires (!detail::HasModifier<NonExtractable, Mods...>) { return m_value; }

private:
	friend struct detail::Access;

	T m_value{};
};

} // namespace strong_typedef

template <typename T, typename Tag, typename... Mods>
using StrongTypedef = strong_typedef::StrongTypedef<T, Tag, Mods...>;

} // namespace bn::base

namespace std {

template <typename T, typename Tag, typename... Mods>
	requires ::bn::base::strong_typedef::detail::HasModifier<::bn::base::strong_typedef::Hashable, Mods...>
struct hash<::bn::base::StrongTypedef<T, Tag, Mods...>>
{
	constexpr std::size_t operator()(const ::bn::base::StrongTypedef<T, Tag, Mods...>& v) const
		noexcept(noexcept(std::hash<T> {}(::bn::base::strong_typedef::detail::Access::Get(v))))
	{
		return std::hash<T> {}(::bn::base::strong_typedef::detail::Access::Get(v));
	}
};

} // namespace std

// Formatting forwards to the underlying type's formatter, so format specs (e.g. {:#x})
// pass through. Enabled only when the type carries the Formattable modifier.
template <typename T, typename Tag, typename... Mods>
	requires ::bn::base::strong_typedef::detail::HasModifier<::bn::base::strong_typedef::Formattable, Mods...>
struct fmt::formatter<::bn::base::StrongTypedef<T, Tag, Mods...>> : fmt::formatter<T>
{
	template <typename FormatContext>
	auto format(const ::bn::base::StrongTypedef<T, Tag, Mods...>& v, FormatContext& ctx) const
	{
		return fmt::formatter<T>::format(::bn::base::strong_typedef::detail::Access::Get(v), ctx);
	}
};
