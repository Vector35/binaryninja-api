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

#include "exceptions.h"
#include "binaryninjacore.h"
#include <stdlib.h>

BinaryNinja::ExceptionWithStackTrace::ExceptionWithStackTrace(const std::string& message)
{
	m_originalMessage = message;
	m_message = message;
	if (getenv("BN_DEBUG_EXCEPTION_TRACES"))
	{
		char* stackTrace = BNGetCurrentStackTraceString();
		if (stackTrace)
		{
			m_stackTrace = stackTrace;
			m_message += "\n";
			m_message += stackTrace;
			BNFreeString(stackTrace);
		}
	}
}


BinaryNinja::ExceptionWithStackTrace::ExceptionWithStackTrace(std::exception_ptr exc1, std::exception_ptr exc2)
{
	m_originalMessage = "";
	m_message = "";
	if (exc1)
	{
		try
		{
			std::rethrow_exception(exc1);
		}
		catch (ExceptionWithStackTrace& stacky)
		{
			m_originalMessage = stacky.m_originalMessage;
			m_message = stacky.m_message;
		}
		catch (std::exception& exc)
		{
			m_originalMessage = exc.what();
			m_message = exc.what();
		}
		catch (...)
		{
			m_originalMessage = "Some unknown exception";
			m_message = "Some unknown exception";
		}
	}
	if (exc2)
	{
		try
		{
			std::rethrow_exception(exc2);
		}
		catch (ExceptionWithStackTrace& stacky)
		{
			m_originalMessage += "\n" + stacky.m_originalMessage;
			m_message += "\n" + stacky.m_message;
		}
		catch (std::exception& exc)
		{
			m_originalMessage = exc.what();
			m_message = exc.what();
		}
		catch (...)
		{
			m_originalMessage = "Some unknown exception";
			m_message = "Some unknown exception";
		}
	}
	if (getenv("BN_DEBUG_EXCEPTION_TRACES"))
	{
		char* stackTrace = BNGetCurrentStackTraceString();
		if (stackTrace)
		{
			m_stackTrace = stackTrace;
			m_message += "\n";
			m_message += stackTrace;
			BNFreeString(stackTrace);
		}
	}
}