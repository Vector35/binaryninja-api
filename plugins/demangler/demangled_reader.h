// Copyright 2016-2026 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include "demangler/demangled_type_node.h"

#include <algorithm>
#include <cstring>
#include <exception>
#include <limits>
#include <string_view>
#include <utility>


class DemangleException: public std::exception
{
	_STD_STRING m_message;

public:
	DemangleException(_STD_STRING msg = "Attempt to read beyond bounds or missing expected character"):
		m_message(std::move(msg))
	{}

	[[nodiscard]] const char* what() const noexcept override { return m_message.c_str(); }
};


template <size_t MaxDepth>
class DemangleNestingGuard
{
	size_t& m_depth;
	size_t m_maxDepth;

public:
	explicit DemangleNestingGuard(size_t& depth, size_t maxDepth = MaxDepth):
		m_depth(depth),
		m_maxDepth(maxDepth)
	{
		m_depth++;
		if (m_depth > m_maxDepth)
		{
			m_depth--;
			throw DemangleException("Detected adversarial mangled string");
		}
	}

	~DemangleNestingGuard()
	{
		m_depth--;
	}

	DemangleNestingGuard(const DemangleNestingGuard&) = delete;
	DemangleNestingGuard(DemangleNestingGuard&&) = delete;
	DemangleNestingGuard& operator=(const DemangleNestingGuard&) = delete;
	DemangleNestingGuard& operator=(DemangleNestingGuard&&) = delete;
};


class DemangleReader
{
	const char* m_begin = nullptr;
	const char* m_ptr = nullptr;
	const char* m_end = nullptr;
	size_t m_maxReadStringLength = std::numeric_limits<size_t>::max();
	bool m_throwOnPeekPastEnd = true;

	void ValidatePrintableAscii() const
	{
		for (const char* p = m_begin; p < m_end; p++)
			if (*p < 0x20 || *p > 0x7e)
				throw DemangleException();
	}

public:
	DemangleReader() = default;

	explicit DemangleReader(const _STD_STRING& data,
		size_t maxReadStringLength = std::numeric_limits<size_t>::max(),
		bool throwOnPeekPastEnd = true):
		m_maxReadStringLength(maxReadStringLength),
		m_throwOnPeekPastEnd(throwOnPeekPastEnd)
	{
		Reset(data);
	}

	void Reset(const _STD_STRING& data)
	{
		m_begin = data.c_str();
		m_ptr = m_begin;
		m_end = m_begin + data.size();
		ValidatePrintableAscii();
	}

	[[nodiscard]] size_t Length() const { return static_cast<size_t>(m_end - m_ptr); }
	[[nodiscard]] size_t GetOffset() const { return static_cast<size_t>(m_ptr - m_begin); }

	void SetOffset(size_t offset)
	{
		size_t length = static_cast<size_t>(m_end - m_begin);
		m_ptr = m_begin + std::min(offset, length);
	}

	void UnRead(size_t count = 1)
	{
		if (count <= GetOffset())
			m_ptr -= count;
	}

	[[nodiscard]] bool PeekMatch(const char* str, size_t len) const
	{
		if (len > Length())
			return false;
		return memcmp(m_ptr, str, len) == 0;
	}

	template <size_t N>
	[[nodiscard]] bool PeekMatch(const char (&str)[N]) const
	{
		return PeekMatch(str, N - 1);
	}

	[[nodiscard]] _STD_STRING PeekString(size_t count = 1) const
	{
		if (count > Length())
			return "\0";
		return _STD_STRING(m_ptr, count);
	}

	[[nodiscard]] char PeekAt(size_t offset) const
	{
		if (offset >= Length())
			throw DemangleException();
		return m_ptr[offset];
	}

	[[nodiscard]] char Peek() const
	{
		if (m_ptr >= m_end)
		{
			if (m_throwOnPeekPastEnd)
				throw DemangleException();
			return '\0';
		}
		return *m_ptr;
	}

	[[nodiscard]] char PeekOr(char fallback = '\0') const
	{
		if (Length() == 0)
			return fallback;
		return *m_ptr;
	}

	[[nodiscard]] const char* GetRaw() const { return m_ptr; }

	void SetRaw(const char* p)
	{
		if (p < m_begin || p > m_end)
			throw DemangleException();
		m_ptr = p;
	}

	[[nodiscard]] char Read()
	{
		if (m_ptr >= m_end)
			throw DemangleException();
		return *m_ptr++;
	}

	_STD_STRING ReadString(size_t count = 1)
	{
		if (count > Length())
			throw DemangleException();
		if (count > m_maxReadStringLength)
			throw DemangleException("Demangled node exceeds maximum length");
		_STD_STRING out(m_ptr, count);
		m_ptr += count;
		return out;
	}

	std::string_view ReadStringView(size_t count = 1)
	{
		if (count > Length())
			throw DemangleException();
		if (count > m_maxReadStringLength)
			throw DemangleException("Demangled node exceeds maximum length");
		std::string_view out(m_ptr, count);
		m_ptr += count;
		return out;
	}

	_STD_STRING ReadUntil(char sentinel)
	{
		const char* found = static_cast<const char*>(memchr(m_ptr, sentinel, m_end - m_ptr));
		if (!found)
			throw DemangleException();
		size_t count = static_cast<size_t>(found - m_ptr);
		_STD_STRING out = ReadString(count);
		Consume(); // sentinel
		return out;
	}

	bool ConsumeIf(char ch)
	{
		if (PeekOr() != ch)
			return false;
		Consume();
		return true;
	}

	bool ConsumeIf(const char* str, size_t len)
	{
		if (!PeekMatch(str, len))
			return false;
		Consume(len);
		return true;
	}

	template <size_t N>
	bool ConsumeIf(const char (&str)[N])
	{
		return ConsumeIf(str, N - 1);
	}

	void Consume(size_t count = 1)
	{
		if (count > Length())
			throw DemangleException();
		m_ptr += count;
	}
};
