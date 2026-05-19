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

// A back-growing segmented array: a directory of pointers to geometrically
// sized chunks. It gives portable, controlled chunk sizing (identical on every
// platform, unlike std::deque), O(1) random access, and a guarantee that
// growth never moves, copies, or reallocates existing elements — so pointers,
// references, and non-end() iterators all survive push_back.

#include "base/assertions.h"
#include "base/compiler.h"

#include <algorithm>
#include <bit>
#include <compare>
#include <cstddef>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>


namespace bn::base {

namespace detail {

// Target byte budgets for the default chunk sizes. Max targets a ~64 KiB chunk.
// Initial targets a ~64 B chunk so small instances have little waste.
constexpr std::size_t kDefaultMaxChunkBytes = 65536;
constexpr std::size_t kDefaultInitialChunkBytes = 64;

// Translate a byte budget into an element count for T: at least one element,
// rounded down to a power of two.
template <class T>
constexpr std::size_t chunk_elems_for_bytes(std::size_t bytes)
{
	return std::bit_floor(std::max<std::size_t>(1, bytes / sizeof(T)));
}

}  // namespace detail

// A segmented array of T with portable chunk sizing and append stability.
//
// Chunk capacities follow a geometric ramp (B, 2B, 4B, ..., C) and then a fixed
// plateau (C, C, C, ...), where B is InitialChunkElems and C is MaxChunkElems,
// both powers of two. The integer params come before the allocator since tuning
// chunks is the common direct-use case. A 0 means "use the byte-budget default
// for T", which gives a three-mode template usage:
//
//   SegmentedVector<T>        — byte-budget defaults (small ramp to ~64 KiB)
//   SegmentedVector<T, N>     — pure fixed-size N-element chunks (no ramp)
//   SegmentedVector<T, B, C>  — explicit ramp from B to C
template <class T,
    std::size_t InitialChunkElems = 0,
    std::size_t MaxChunkElems = 0,
    class Allocator = std::allocator<T>>
class SegmentedVector
{
private:
	using AllocTraits = std::allocator_traits<Allocator>;

	static_assert(std::is_same_v<typename AllocTraits::pointer, T*>,
	    "SegmentedVector supports raw-pointer allocators only (no fancy pointers)");

	// Single-arg form (`<T, N>`) collapses the ramp by treating Max as Initial.
	static constexpr std::size_t C = MaxChunkElems != 0
	    ? MaxChunkElems
	    : (InitialChunkElems != 0 ? InitialChunkElems
	                              : detail::chunk_elems_for_bytes<T>(detail::kDefaultMaxChunkBytes));
	static constexpr std::size_t B = InitialChunkElems != 0
	    ? InitialChunkElems
	    : (std::min)(detail::chunk_elems_for_bytes<T>(detail::kDefaultInitialChunkBytes), C);
	static_assert(std::has_single_bit(B) && std::has_single_bit(C),
	    "chunk capacities must be powers of two");
	static_assert(B <= C, "InitialChunkElems must not exceed MaxChunkElems");
	// Bound MaxChunkElems so kRampCapacity (2*C - B), chunk_base shifts, and
	// other internal arithmetic stay well within size_t.
	static_assert(C <= (std::numeric_limits<std::size_t>::max() / 4),
	    "MaxChunkElems too large; chunk-sizing arithmetic could overflow");

public:
	using value_type = T;
	using allocator_type = Allocator;
	using size_type = std::size_t;
	using difference_type = std::ptrdiff_t;
	using reference = T&;
	using const_reference = const T&;
	using pointer = T*;
	using const_pointer = const T*;

private:
	static constexpr size_type kLog2C = std::bit_width(C) - 1;
	static constexpr size_type kLog2B = std::bit_width(B) - 1;
	static constexpr size_type kRampChunkCount = kLog2C - kLog2B + 1;
	static constexpr size_type kRampCapacity = 2 * C - B;

	struct Location
	{
		size_type chunk;
		size_type offset;
	};

	// Capacity of chunk `k`.
	static constexpr size_type chunk_capacity(size_type k) noexcept
	{
		if (k < kRampChunkCount)
			return B << k;
		return C;
	}

	// Cumulative capacity of chunks 0..k-1, i.e. the logical index of the first
	// element of chunk `k` and the total capacity of the first `k` chunks.
	static constexpr size_type chunk_base(size_type k) noexcept
	{
		if (k <= kRampChunkCount)
			return (B << k) - B;
		return kRampCapacity + (k - kRampChunkCount) * C;
	}

	// Decompose a logical element index into (chunk, offset). O(1).
	static constexpr Location locate(size_type i) noexcept
	{
		if (i < kRampCapacity)
		{
			size_type q = (i >> kLog2B) + 1;
			size_type k = std::bit_width(q) - 1;
			return {k, i - ((B << k) - B)};
		}
		size_type j = i - kRampCapacity;
		return {kRampChunkCount + (j >> kLog2C), j & (C - 1)};
	}

	// Number of chunks required to hold `n` elements.
	static constexpr size_type chunks_for_size(size_type n) noexcept
	{
		if (n == 0)
			return 0;
		return locate(n - 1).chunk + 1;
	}

	template <bool Const>
	class iterator_impl
	{
		using container = std::conditional_t<Const, const SegmentedVector, SegmentedVector>;

		container* m_owner = nullptr;
		size_type m_index = 0;

		friend class SegmentedVector;
		template <bool>
		friend class iterator_impl;

		iterator_impl(container* owner, size_type index) noexcept : m_owner(owner), m_index(index) {}

	public:
		using iterator_category = std::random_access_iterator_tag;
		using iterator_concept = std::random_access_iterator_tag;
		using value_type = T;
		using difference_type = std::ptrdiff_t;
		using pointer = std::conditional_t<Const, const T*, T*>;
		using reference = std::conditional_t<Const, const T&, T&>;

		iterator_impl() = default;

		// Implicit conversion from iterator to const_iterator. Templated so it is
		// never the copy constructor.
		template <bool OtherConst>
		    requires (Const && !OtherConst)
		iterator_impl(const iterator_impl<OtherConst>& other) noexcept
		    : m_owner(other.m_owner), m_index(other.m_index)
		{}

		reference operator*() const { return (*m_owner)[m_index]; }
		pointer operator->() const { return std::addressof((*m_owner)[m_index]); }
		reference operator[](difference_type n) const { return (*m_owner)[m_index + n]; }

		iterator_impl& operator++() noexcept
		{
			++m_index;
			return *this;
		}
		iterator_impl operator++(int) noexcept
		{
			iterator_impl t = *this;
			++m_index;
			return t;
		}
		iterator_impl& operator--() noexcept
		{
			--m_index;
			return *this;
		}
		iterator_impl operator--(int) noexcept
		{
			iterator_impl t = *this;
			--m_index;
			return t;
		}
		iterator_impl& operator+=(difference_type n) noexcept
		{
			m_index += n;
			return *this;
		}
		iterator_impl& operator-=(difference_type n) noexcept
		{
			m_index -= n;
			return *this;
		}

		friend iterator_impl operator+(iterator_impl it, difference_type n) noexcept
		{
			it.m_index += n;
			return it;
		}
		friend iterator_impl operator+(difference_type n, iterator_impl it) noexcept
		{
			it.m_index += n;
			return it;
		}
		friend iterator_impl operator-(iterator_impl it, difference_type n) noexcept
		{
			it.m_index -= n;
			return it;
		}

		template <bool C2>
		difference_type operator-(const iterator_impl<C2>& other) const noexcept
		{
			BN_ASSERT(m_owner == other.m_owner);
			return static_cast<difference_type>(m_index) - static_cast<difference_type>(other.m_index);
		}

		template <bool C2>
		bool operator==(const iterator_impl<C2>& other) const noexcept
		{
			BN_ASSERT(m_owner == other.m_owner);
			return m_index == other.m_index;
		}
		template <bool C2>
		std::strong_ordering operator<=>(const iterator_impl<C2>& other) const noexcept
		{
			BN_ASSERT(m_owner == other.m_owner);
			return m_index <=> other.m_index;
		}
	};

public:
	using iterator = iterator_impl<false>;
	using const_iterator = iterator_impl<true>;
	using reverse_iterator = std::reverse_iterator<iterator>;
	using const_reverse_iterator = std::reverse_iterator<const_iterator>;

	SegmentedVector() = default;

	explicit SegmentedVector(const Allocator& alloc) noexcept :
	    m_directory(DirAlloc(alloc)), m_alloc(alloc)
	{}

	explicit SegmentedVector(size_type count, const Allocator& alloc = Allocator()) :
	    m_directory(DirAlloc(alloc)), m_alloc(alloc)
	{
		resize(count);
	}

	SegmentedVector(size_type count, const T& value, const Allocator& alloc = Allocator()) :
	    m_directory(DirAlloc(alloc)), m_alloc(alloc)
	{
		resize(count, value);
	}

	template <class InputIt>
	    requires std::input_iterator<InputIt>
	SegmentedVector(InputIt first, InputIt last, const Allocator& alloc = Allocator()) :
	    m_directory(DirAlloc(alloc)), m_alloc(alloc)
	{
		// The input-iterator append loop (used when distance() is unavailable)
		// builds element-by-element with no internal rollback. A throw here
		// would leak the already-built elements/chunks because the destructor
		// does not run on a failed construction.
		try
		{
			append_range(first, last);
		}
		catch (...)
		{
			destroy_and_free_all();
			throw;
		}
	}

	SegmentedVector(std::initializer_list<T> init, const Allocator& alloc = Allocator()) :
	    m_directory(DirAlloc(alloc)), m_alloc(alloc)
	{
		append_range(init.begin(), init.end());
	}

	SegmentedVector(const SegmentedVector& other)
	    requires std::is_copy_constructible_v<T>
	    : SegmentedVector(other, AllocTraits::select_on_container_copy_construction(other.m_alloc), CopyTag {})
	{}

	SegmentedVector(SegmentedVector&& other) noexcept :
	    m_directory(std::move(other.m_directory)), m_size(other.m_size), m_alloc(std::move(other.m_alloc))
	{
		other.m_size = 0;
	}

	~SegmentedVector() { destroy_and_free_all(); }

	SegmentedVector& operator=(const SegmentedVector& other)
	    requires std::is_copy_constructible_v<T>
	{
		if (this == &other)
			return *this;

		if constexpr (AllocTraits::propagate_on_container_copy_assignment::value)
		{
			if (!is_same_allocator(other.m_alloc))
			{
				// Allocator must change and is not interchangeable. Build the new allocator
				// + empty directory off to the side first so that if either copy throws,
				// this is unchanged. The destroy/construct of m_directory must not be
				// separated by a throwing step or the member is left destroyed, so the
				// potentially throwing m_alloc assignment is performed first.
				Allocator newAlloc(other.m_alloc);
				Directory newDir{DirAlloc(newAlloc)};

				destroy_and_free_all();
				m_alloc = std::move(newAlloc);
				std::destroy_at(&m_directory);
				std::construct_at(&m_directory, std::move(newDir));

				append_range(other.begin(), other.end());
				return *this;
			}
			m_alloc = other.m_alloc;
		}

		// Same allocator, so we can reuse existing chunks. Copy-assign across the
		// overlapping prefix, then destroy the tail (shrink) or append the tail (grow).
		// Both containers share the same chunk-sizing policy, so chunk k holds the same
		// logical index range in each, making the overlap a flat per-chunk T* copy.
		const size_type common = (std::min)(m_size, other.m_size);
		for (size_type chunk = 0, remaining = common; remaining > 0; ++chunk)
		{
			const size_type n = (std::min)(remaining, chunk_capacity(chunk));
			std::copy(other.m_directory[chunk], other.m_directory[chunk] + n, m_directory[chunk]);
			remaining -= n;
		}
		if (other.m_size < m_size)
		{
			destroy_range(other.m_size, m_size);
			m_size = other.m_size;
			trim_to(chunks_for_size(m_size));
		}
		else if (other.m_size > m_size)
		{
			append_range(other.begin() + m_size, other.end());
		}
		return *this;
	}

	SegmentedVector& operator=(SegmentedVector&& other) noexcept(
	    AllocTraits::propagate_on_container_move_assignment::value || AllocTraits::is_always_equal::value)
	{
		if (this == &other)
			return *this;

		destroy_and_free_all();

		constexpr bool propagate_allocator = AllocTraits::propagate_on_container_move_assignment::value;
		if (propagate_allocator || is_same_allocator(other.m_alloc))
		{
			if constexpr (propagate_allocator)
				m_alloc = std::move(other.m_alloc);

			m_directory = std::move(other.m_directory);
			m_size = other.m_size;
			other.m_size = 0;
		}
		else
		{
			// Unequal, non-propagating allocators. The destination cannot own the
			// source's storage, so we must move elements individually.
			append_range(std::make_move_iterator(other.begin()), std::make_move_iterator(other.end()));
		}
		return *this;
	}

	SegmentedVector& operator=(std::initializer_list<T> init)
	{
		assign(init.begin(), init.end());
		return *this;
	}

	void assign(size_type count, const T& value)
	{
		const size_type common = (std::min)(m_size, count);
		// Copy-assign across the overlap chunk-by-chunk so the inner loop is a flat T* write.
		for (size_type chunk = 0, remaining = common; remaining > 0; ++chunk)
		{
			const size_type n = (std::min)(remaining, chunk_capacity(chunk));
			T* dst = m_directory[chunk];
			for (size_type i = 0; i < n; ++i)
				dst[i] = value;
			remaining -= n;
		}
		if (count < m_size)
		{
			destroy_range(count, m_size);
			m_size = count;
			trim_to(chunks_for_size(m_size));
		}
		else if (count > m_size)
		{
			bulk_construct(count - m_size, [this, &value](T* slot) { AllocTraits::construct(m_alloc, slot, value); });
		}
	}

	template <class InputIt>
	    requires std::input_iterator<InputIt>
	void assign(InputIt first, InputIt last)
	{
		if constexpr (std::forward_iterator<InputIt>)
		{
			const size_type otherSize = static_cast<size_type>(std::distance(first, last));
			const size_type common = (std::min)(m_size, otherSize);
			// Chunk-by-chunk overlap copy on the destination. The source is iterated
			// element-by-element since the iterator has no special structure.
			for (size_type chunk = 0, remaining = common; remaining > 0; ++chunk)
			{
				const size_type n = (std::min)(remaining, chunk_capacity(chunk));
				T* dst = m_directory[chunk];
				for (size_type i = 0; i < n; ++i, ++first)
					dst[i] = *first;
				remaining -= n;
			}
			if (otherSize < m_size)
			{
				destroy_range(otherSize, m_size);
				m_size = otherSize;
				trim_to(chunks_for_size(m_size));
			}
			else if (otherSize > m_size)
			{
				append_range(first, last);
			}
		}
		else
		{
			// Input iterator, so we don't know the size up front. Copy-assign
			// until either side is exhausted, then trim or append.
			size_type i = 0;
			for (; i < m_size && first != last; ++i, ++first)
				(*this)[i] = *first;
			if (i < m_size)
			{
				destroy_range(i, m_size);
				m_size = i;
				trim_to(chunks_for_size(m_size));
			}
			else
			{
				append_range(first, last);
			}
		}
	}

	void assign(std::initializer_list<T> init) { assign(init.begin(), init.end()); }

	allocator_type get_allocator() const noexcept { return m_alloc; }


	reference operator[](size_type i)
	{
		BN_ASSERT(i < m_size);
		return *slot_at(i);
	}

	const_reference operator[](size_type i) const
	{
		BN_ASSERT(i < m_size);
		Location loc = locate(i);
		return m_directory[loc.chunk][loc.offset];
	}

	reference at(size_type i)
	{
		if (i >= m_size)
			throw std::out_of_range("SegmentedVector::at");
		return (*this)[i];
	}

	const_reference at(size_type i) const
	{
		if (i >= m_size)
			throw std::out_of_range("SegmentedVector::at");
		return (*this)[i];
	}

	reference front()
	{
		BN_ASSERT(m_size > 0);
		return (*this)[0];
	}
	const_reference front() const
	{
		BN_ASSERT(m_size > 0);
		return (*this)[0];
	}
	reference back()
	{
		BN_ASSERT(m_size > 0);
		return (*this)[m_size - 1];
	}
	const_reference back() const
	{
		BN_ASSERT(m_size > 0);
		return (*this)[m_size - 1];
	}


	iterator begin() noexcept { return iterator(this, 0); }
	const_iterator begin() const noexcept { return const_iterator(this, 0); }
	iterator end() noexcept { return iterator(this, m_size); }
	const_iterator end() const noexcept { return const_iterator(this, m_size); }
	const_iterator cbegin() const noexcept { return const_iterator(this, 0); }
	const_iterator cend() const noexcept { return const_iterator(this, m_size); }

	reverse_iterator rbegin() noexcept { return reverse_iterator(end()); }
	const_reverse_iterator rbegin() const noexcept { return const_reverse_iterator(end()); }
	reverse_iterator rend() noexcept { return reverse_iterator(begin()); }
	const_reverse_iterator rend() const noexcept { return const_reverse_iterator(begin()); }
	const_reverse_iterator crbegin() const noexcept { return const_reverse_iterator(cend()); }
	const_reverse_iterator crend() const noexcept { return const_reverse_iterator(cbegin()); }


	bool empty() const noexcept { return m_size == 0; }
	size_type size() const noexcept { return m_size; }
	size_type max_size() const noexcept { return AllocTraits::max_size(m_alloc); }

	// Total element slots across all currently allocated chunks.
	size_type capacity() const noexcept { return chunk_base(m_directory.size()); }

	void reserve(size_type n)
	{
		if (n <= capacity())
			return;
		size_type oldChunkCount = m_directory.size();
		try
		{
			while (capacity() < n)
				append_chunk();
		}
		catch (...)
		{
			trim_to(oldChunkCount);
			throw;
		}
	}

	// Releases the retained spare chunk and trims to the minimum that holds
	// size() elements. On an empty container this returns to the
	// zero-allocation state.
	void shrink_to_fit()
	{
		trim_to(chunks_for_size(m_size));
		m_directory.shrink_to_fit();
	}

	// Destroys all elements and frees all chunks except one, retained as a
	// spare. A cleared container is not the same as a default-constructed one.
	void clear() noexcept
	{
		destroy_range(0, m_size);
		m_size = 0;
		trim_to(1);
	}

	void push_back(const T& value) { emplace_back(value); }
	void push_back(T&& value) { emplace_back(std::move(value)); }

	template <class... Args>
	reference emplace_back(Args&&... args)
	{
		Location loc = locate(m_size);
		bool allocated = false;
		if (loc.chunk >= m_directory.size())
		{
			append_chunk();
			allocated = true;
		}
		T* slot = m_directory[loc.chunk] + loc.offset;
		try
		{
			AllocTraits::construct(m_alloc, slot, std::forward<Args>(args)...);
		}
		catch (...)
		{
			if (allocated)
				pop_chunk();
			throw;
		}
		++m_size;
		return *slot;
	}

	void pop_back()
	{
		BN_ASSERT(m_size > 0);
		--m_size;
		Location loc = locate(m_size);
		AllocTraits::destroy(m_alloc, m_directory[loc.chunk] + loc.offset);
		trim_to(chunks_for_size(m_size) + 1);
	}

	// Appends [first, last). For a forward iterator the required capacity is
	// reserved up front and the elements are constructed chunk-by-chunk with a
	// flat T* inner loop, so the compiler can vectorize for a trivial T. For an
	// input iterator the count is unknown and each element goes through
	// emplace_back.
	template <class InputIt>
	    requires std::input_iterator<InputIt>
	void append_range(InputIt first, InputIt last)
	{
		if constexpr (std::forward_iterator<InputIt>)
		{
			size_type n = static_cast<size_type>(std::distance(first, last));
			bulk_construct(n, [this, &first](T* slot) {
				// Advance before constructing so a throwing `++first` cannot
				// leave a built-but-uncounted element behind. Forward iterators
				// guarantee the reference stays valid after the increment.
				// `auto&&` to work with move_iterator.
				auto&& val = *first;
				++first;
				AllocTraits::construct(m_alloc, slot, static_cast<decltype(val)>(val));
			});
		}
		else
		{
			for (; first != last; ++first)
				emplace_back(*first);
		}
	}

	iterator insert(const_iterator pos, const T& value) { return emplace(pos, value); }
	iterator insert(const_iterator pos, T&& value) { return emplace(pos, std::move(value)); }

	iterator insert(const_iterator pos, size_type count, const T& value)
	{
		BN_ASSERT(pos.m_owner == this);
		size_type p = pos.m_index;
		size_type oldSize = m_size;
		bulk_construct(count, [this, &value](T* slot) { AllocTraits::construct(m_alloc, slot, value); });
		std::rotate(begin() + p, begin() + oldSize, end());
		return iterator(this, p);
	}

	template <class InputIt>
	    requires std::input_iterator<InputIt>
	iterator insert(const_iterator pos, InputIt first, InputIt last)
	{
		BN_ASSERT(pos.m_owner == this);
		size_type p = pos.m_index;
		size_type oldSize = m_size;
		append_range(first, last);
		std::rotate(begin() + p, begin() + oldSize, end());
		return iterator(this, p);
	}

	iterator insert(const_iterator pos, std::initializer_list<T> init)
	{
		return insert(pos, init.begin(), init.end());
	}

	template <class... Args>
	iterator emplace(const_iterator pos, Args&&... args)
	{
		BN_ASSERT(pos.m_owner == this);
		size_type p = pos.m_index;
		size_type oldSize = m_size;
		emplace_back(std::forward<Args>(args)...);
		std::rotate(begin() + p, begin() + oldSize, end());
		return iterator(this, p);
	}

	iterator erase(const_iterator pos) { return erase(pos, pos + 1); }

	iterator erase(const_iterator first, const_iterator last)
	{
		BN_ASSERT(first.m_owner == this && last.m_owner == this);
		size_type f = first.m_index;
		size_type l = last.m_index;
		BN_ASSERT(f <= l && l <= m_size);
		if (f == l)
			return iterator(this, f);

		// Move the survivors [l, m_size) down to start at f, leaving the erased
		// elements at the tail, then drop the tail.
		std::rotate(begin() + f, begin() + l, end());
		size_type n = l - f;
		destroy_range(m_size - n, m_size);
		m_size -= n;
		trim_to(chunks_for_size(m_size) + 1);
		return iterator(this, f);
	}

	void resize(size_type count)
	{
		if (count < m_size)
			shrink_to(count);
		else if (count > m_size)
			bulk_construct(count - m_size, [this](T* slot) { AllocTraits::construct(m_alloc, slot); });
	}

	void resize(size_type count, const T& value)
	{
		if (count < m_size)
			shrink_to(count);
		else if (count > m_size)
			bulk_construct(count - m_size, [this, &value](T* slot) { AllocTraits::construct(m_alloc, slot, value); });
	}

	void swap(SegmentedVector& other) noexcept(
	    AllocTraits::propagate_on_container_swap::value || AllocTraits::is_always_equal::value)
	{
		// Standard says swapping containers with unequal non-propagating allocators is undefined.
		BN_ASSERT(AllocTraits::propagate_on_container_swap::value || is_same_allocator(other.m_alloc));
		using std::swap;
		if constexpr (AllocTraits::propagate_on_container_swap::value)
			swap(m_alloc, other.m_alloc);

		m_directory.swap(other.m_directory);
		swap(m_size, other.m_size);
	}


	// Both operands share the chunk-sizing policy, so chunk k covers the same
	// logical index range in each. Comparing chunk-by-chunk hands the compiler a
	// flat contiguous T* range per chunk which will hopefully turn into a memcmp
	// for trivial T.
	friend bool operator==(const SegmentedVector& a, const SegmentedVector& b)
	{
		if (a.m_size != b.m_size)
			return false;

		for (size_type chunk = 0, remaining = a.m_size; remaining > 0; ++chunk)
		{
			size_type n = (std::min)(remaining, chunk_capacity(chunk));
			const T* pa = a.m_directory[chunk];
			if (!std::equal(pa, pa + n, b.m_directory[chunk]))
				return false;

			remaining -= n;
		}
		return true;
	}

	// A template (with a defaulted parameter) so the return type is instantiated
	// only when operator<=> is actually used. This allows `SegmentedVector` to work
	// with a `T` that has no defined ordering, since the substitution failure simply
	// removes <=> from consideration.
	template <class U = T>
	friend auto operator<=>(const SegmentedVector& a, const SegmentedVector& b)
	    -> decltype(std::lexicographical_compare_three_way(
	        std::declval<const U*>(), std::declval<const U*>(), std::declval<const U*>(), std::declval<const U*>()))
	{
		using order_type = decltype(std::lexicographical_compare_three_way(
		    std::declval<const U*>(), std::declval<const U*>(), std::declval<const U*>(), std::declval<const U*>()));
		size_type remaining = (std::min)(a.m_size, b.m_size);
		for (size_type chunk = 0; remaining > 0; ++chunk)
		{
			size_type n = (std::min)(remaining, chunk_capacity(chunk));
			const T* pa = a.m_directory[chunk];
			const T* pb = b.m_directory[chunk];
			if (order_type c = std::lexicographical_compare_three_way(pa, pa + n, pb, pb + n); c != 0)
				return c;
			remaining -= n;
		}
		return order_type(a.m_size <=> b.m_size);
	}

private:
	struct CopyTag {};

	// Delegated to by the copy constructor so the chosen allocator is computed only once.
	SegmentedVector(const SegmentedVector& other, const Allocator& alloc, CopyTag) :
	    m_directory(DirAlloc(alloc)), m_alloc(alloc)
	{
		append_range(other.begin(), other.end());
	}

	using DirAlloc = typename AllocTraits::template rebind_alloc<T*>;
	using Directory = std::vector<T*, DirAlloc>;

	// Whether storage allocated by `other` can be freed by this container's
	// allocator and vice versa — true when the allocator type is always-equal or
	// the two instances compare equal. Decides whether move/copy assignment can
	// adopt storage directly or must fall back to per-element transfer.
	bool is_same_allocator(const Allocator& other) const noexcept
	{
		return AllocTraits::is_always_equal::value || m_alloc == other;
	}

	Directory m_directory;
	size_type m_size = 0;
	BN_NO_UNIQUE_ADDRESS Allocator m_alloc;

	T* allocate_chunk(size_type chunkIndex)
	{
		return AllocTraits::allocate(m_alloc, chunk_capacity(chunkIndex));
	}

	void deallocate_chunk(T* chunk, size_type chunkIndex) noexcept
	{
		AllocTraits::deallocate(m_alloc, chunk, chunk_capacity(chunkIndex));
	}

	// Appends one chunk to the directory. On throw, the directory is unchanged.
	void append_chunk()
	{
		size_type idx = m_directory.size();
		T* chunk = allocate_chunk(idx);
		try
		{
			m_directory.push_back(chunk);
		}
		catch (...)
		{
			deallocate_chunk(chunk, idx);
			throw;
		}
	}

	// Frees the trailing chunk. Used to undo append_chunk on an element-
	// construction failure. The trailing chunk must be empty.
	void pop_chunk() noexcept
	{
		size_type idx = m_directory.size() - 1;
		deallocate_chunk(m_directory[idx], idx);
		m_directory.pop_back();
	}

	// Frees trailing chunks until at most `chunksToKeep` remain.
	void trim_to(size_type chunksToKeep) noexcept
	{
		while (m_directory.size() > chunksToKeep)
			pop_chunk();
	}

	T* slot_at(size_type i) noexcept
	{
		Location loc = locate(i);
		return m_directory[loc.chunk] + loc.offset;
	}

	void destroy_range(size_type first, size_type last) noexcept
	{
		for (size_type i = first; i < last; ++i)
			AllocTraits::destroy(m_alloc, slot_at(i));
	}

	void shrink_to(size_type count) noexcept
	{
		destroy_range(count, m_size);
		m_size = count;
		trim_to(chunks_for_size(m_size) + 1);
	}

	// Destroys all elements and frees all chunks, leaving the container empty.
	void destroy_and_free_all() noexcept
	{
		destroy_range(0, m_size);
		m_size = 0;
		trim_to(0);
	}

	// Appends `count` new slots, calling `construct(slot)` on each in order to
	// build the element there. Reserves up front and then walks chunk-by-chunk,
	// so `construct` runs in a flat per-chunk inner loop over contiguous T* —
	// one locate() per chunk rather than per element.
	// 
	// Strong guarantee: on a throwing construction the previously built elements
	// are destroyed and any chunks allocated by this call are released, so size()
	// and capacity() are unchanged.
	template <class Construct>
	void bulk_construct(size_type count, Construct construct)
	{
		if (count == 0)
			return;

		if (count > max_size() - m_size)
			throw std::length_error("SegmentedVector: size would exceed max_size");

		size_type oldSize = m_size;
		size_type oldChunkCount = m_directory.size();
		try
		{
			size_type target = m_size + count;
			reserve(target);
			while (m_size < target)
			{
				Location loc = locate(m_size);
				T* base = m_directory[loc.chunk] + loc.offset;
				size_type batch = (std::min)(chunk_capacity(loc.chunk) - loc.offset, target - m_size);
				for (size_type i = 0; i < batch; ++i)
				{
					construct(base + i);
					++m_size;
				}
			}
		}
		catch (...)
		{
			destroy_range(oldSize, m_size);
			m_size = oldSize;
			trim_to(oldChunkCount);
			throw;
		}
	}
};

template <class T, std::size_t I, std::size_t M, class A>
void swap(SegmentedVector<T, I, M, A>& a, SegmentedVector<T, I, M, A>& b) noexcept(noexcept(a.swap(b)))
{
	a.swap(b);
}

}  // namespace bn::base
