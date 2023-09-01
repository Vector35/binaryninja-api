// Copyright (c) 2015-2023 Vector 35 Inc
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

#include <exception>
#include <string>

#ifndef BINARYNINJACORE_LIBRARY
namespace BinaryNinja
{
	struct ExceptionWithStackTrace : std::exception
	{
		std::string m_originalMessage;
		std::string m_message;
		std::string m_stackTrace;
		ExceptionWithStackTrace(const std::string& message);
		ExceptionWithStackTrace(std::exception_ptr exc1, std::exception_ptr exc2);
		const char* what() const noexcept override
		{
			return m_message.c_str();
		}
	};
}
#endif

#ifdef BINARYNINJACORE_LIBRARY
using ExceptionWithStackTrace = BinaryNinjaCore::ExceptionWithStackTrace;
#else
using ExceptionWithStackTrace = BinaryNinja::ExceptionWithStackTrace;
#endif