// Copyright (c) 2015-2024 Vector 35 Inc
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

#ifdef BINARYNINJACORE_LIBRARY
#include "binaryninjacore_global.h"
namespace BinaryNinjaCore
{
#else
using namespace std;
#endif

	template <typename T>
	class GenericRange
	{
		uint64_t m_start;
		uint64_t m_end;
		vector<T> m_items;

	public:
		GenericRange(uint64_t s) : m_start(s), m_end(0) { }
		GenericRange(uint64_t s, uint64_t e, const T& item) : m_start(s), m_end(e), m_items{item} {}
		GenericRange(uint64_t s, uint64_t e, const vector<T>& items) : m_start(s), m_end(e), m_items{items} {}

		bool operator<(const GenericRange& other) const
		{
			if (m_start != other.m_start)
				return m_start < other.m_start;
			return m_end < other.m_end;
		}

		uint64_t GetStart() const { return m_start; }
		uint64_t GetEnd() const { return m_end; }
		const vector<T>& GetItems() const { return m_items; }
		vector<T>& GetMutableItems() { return m_items; }

		bool overlaps(const GenericRange& other) const { return !(other.m_start > m_end || m_start > other.m_end); }

		vector<GenericRange> split(const GenericRange& nextInterval) const
		{
			vector<GenericRange> result;
			if (overlaps(nextInterval))
			{
				// Find overlap start and end
				uint64_t intersectionStart = std::max(m_start, nextInterval.m_start);
				uint64_t intersectionEnd = std::min(m_end, nextInterval.m_end);

				// Add part of this section to before the intersecting region if it starts earlier
				if (m_start < intersectionStart)
					result.push_back({m_start, intersectionStart - 1, m_items});

				// Add the intersecting range, plus both sets of items
				GenericRange intersection(intersectionStart, intersectionEnd, m_items);
				intersection.m_items.insert(intersection.m_items.end(), nextInterval.m_items.begin(), nextInterval.m_items.end());
				result.push_back(intersection);

				// If the an interval's end is after the intersection (only up to one will be) add it after
				if (nextInterval.m_end > intersectionEnd)
					result.push_back({intersectionEnd + 1, nextInterval.m_end, nextInterval.m_items});
				else if (m_end > intersectionEnd)
					result.push_back({intersectionEnd + 1, m_end, m_items});
			}

			return result;
		}
	};

	// A map of ranges to items. The ranges are flattened and sorted, and the map is used to quickly find the items. Range values are inclusive.
	template <typename T>
	class GenericRangeMap
	{
		vector<GenericRange<T>> m_sourceRanges;
		vector<GenericRange<T>> m_flattenedRanges;
		map<uint64_t, GenericRange<T>> m_rangeMap;

		void populateRangeMap()
		{
			uint64_t nextStart = 0;
			for (const auto& i : m_flattenedRanges)
			{
				if (i.GetStart() > nextStart)
					m_rangeMap.emplace(nextStart, GenericRange<T>(nextStart, i.GetStart() - 1, vector<T>()));

				m_rangeMap.emplace(i.GetStart(), GenericRange<T>(i.GetStart(), i.GetEnd(), i.GetItems()));
				nextStart = i.GetEnd();
				if (nextStart != std::numeric_limits<uint64_t>::max())
					nextStart++;
			}

			if (nextStart != std::numeric_limits<uint64_t>::max())
				m_rangeMap.emplace(nextStart, GenericRange<T>(nextStart, std::numeric_limits<uint64_t>::max(), vector<T>()));
		}

	public:
		static void flatten(vector<GenericRange<T>>& intervals)
		{
			// Make a flat list of intervals, with each interval having all elements found in it
			// TODO: using a vector isn't ideal, since each modification not at front or back is O(n)
			std::sort(intervals.begin(), intervals.end());
			auto itr = intervals.begin();
			while (itr != intervals.end())
			{
				auto currentRange = *itr;
				auto nextRange = std::next(itr);
				if (nextRange == intervals.end()) // This is the last interval
					break;

				if (auto splitRanges = currentRange.split(*nextRange); splitRanges.size())
				{
					itr = intervals.erase(itr, std::next(nextRange)); // Remove the two source ranges that were split
					size_t resetIndex = intervals.size() + splitRanges.size() - 1; // This is where the iterator will be moved to after inserting new ranges
					for (const auto& range : splitRanges)
					{
						// For each split range, insert it in its sorted position
						auto rangeInsertItr = std::upper_bound(intervals.begin(), intervals.end(), range);
						size_t rangeInsertIndex = rangeInsertItr - intervals.begin();
						intervals.insert(rangeInsertItr, range);
						// Move the reset index to before the lowest inserted range's index; everything before is still sorted
						resetIndex = std::min(resetIndex, rangeInsertIndex == 0 ? 0 : rangeInsertIndex - 1);
					}
					itr = intervals.begin() + resetIndex;
				}
				else
					++itr;
			}
		}

		GenericRangeMap()
		{
			populateRangeMap();
		}

		GenericRangeMap(const vector<GenericRange<T>>& ranges)
		{
			m_sourceRanges = ranges;
			m_flattenedRanges = ranges;
			flatten(m_flattenedRanges);
			populateRangeMap();
		}

		GenericRangeMap(const vector<GenericRange<T>>& ranges, std::function<void(vector<T>&)> orderingStrategy)
		{
			m_sourceRanges = ranges;
			m_flattenedRanges = ranges;
			flatten(m_flattenedRanges);
			if (orderingStrategy)
			{
				for (auto& i : m_flattenedRanges)
					orderingStrategy(i.GetMutableItems());
			}
			populateRangeMap();
		}

		const vector<GenericRange<T>>& GetSourceRanges() const { return m_sourceRanges; }
		const vector<GenericRange<T>>& GetRanges() const { return m_flattenedRanges; }

		const vector<T>& GetItemsAt(uint64_t addr) const
		{
			if (auto itr = m_rangeMap.upper_bound(addr); itr != m_rangeMap.begin())
			{
				--itr;
				return itr->second.GetItems();
			}

			throw std::out_of_range("GenericRangeMap::GetItemsAt - Address not found in any range!");
		}

		const GenericRange<T>& GetGenericRangeAt(uint64_t addr) const
		{
			if (auto itr = m_rangeMap.upper_bound(addr); itr != m_rangeMap.begin())
			{
				--itr;
				return itr->second;
			}

			throw std::out_of_range("GenericRangeMap::GetGenericRangeAt - Address not found in any range!");
		}

		GenericRange<T>& GetMutableGenericRangeAt(uint64_t addr)
		{
			if (auto itr = m_rangeMap.upper_bound(addr); itr != m_rangeMap.begin())
			{
				--itr;
				return itr->second;
			}

			throw std::out_of_range("GenericRangeMap::GetMutableGenericRangeAt - Address not found in any range!");
		}

		std::optional<std::pair<uint64_t, uint64_t>> GetNextValidRange(uint64_t addr, std::function<bool(const GenericRange<T>&)> predicate) const
		{
			auto itr = m_rangeMap.upper_bound(addr);
			if (itr != m_rangeMap.begin())
				--itr;

			while (itr != m_rangeMap.end())
			{
				if (predicate(itr->second))
					return std::make_pair(itr->second.GetStart(), itr->second.GetEnd());
				++itr;
			}

			return std::nullopt;
		}

		std::optional<std::pair<uint64_t, uint64_t>> GetPreviousValidRange(uint64_t addr, std::function<bool(const GenericRange<T>&)> predicate) const
		{
			auto itr = m_rangeMap.upper_bound(addr);
			if (itr != m_rangeMap.begin())
				--itr;

			while (itr != m_rangeMap.begin())
			{
				if (predicate(itr->second))
					return std::make_pair(itr->second.GetStart(), itr->second.GetEnd());
				--itr;
			}

			return std::nullopt;
		}
	};

#ifdef BINARYNINJACORE_LIBRARY
}
#endif
