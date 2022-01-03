// Copyright (c) 2015-2022 Vector 35 Inc
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

#define _CRT_SECURE_NO_WARNINGS
#include <stdarg.h>
#include <stdio.h>
#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


void LogListener::LogMessageCallback(void* ctxt, BNLogLevel level, const char* msg)
{
	LogListener* listener = (LogListener*)ctxt;
	listener->LogMessage(level, msg);
}


void LogListener::CloseLogCallback(void* ctxt)
{
	LogListener* listener = (LogListener*)ctxt;
	listener->CloseLog();
}


BNLogLevel LogListener::GetLogLevelCallback(void* ctxt)
{
	LogListener* listener = (LogListener*)ctxt;
	return listener->GetLogLevel();
}


void LogListener::RegisterLogListener(LogListener* listener)
{
	BNLogListener callbacks;
	callbacks.context = listener;
	callbacks.log = LogMessageCallback;
	callbacks.close = CloseLogCallback;
	callbacks.getLogLevel = GetLogLevelCallback;
	BNRegisterLogListener(&callbacks);
}


void LogListener::UnregisterLogListener(LogListener* listener)
{
	BNLogListener callbacks;
	callbacks.context = listener;
	callbacks.log = LogMessageCallback;
	callbacks.close = CloseLogCallback;
	BNUnregisterLogListener(&callbacks);
}


void LogListener::UpdateLogListeners()
{
	BNUpdateLogListeners();
}


static void PerformLog(BNLogLevel level, const char* fmt, va_list args)
{
#if defined(_MSC_VER)
	int len = _vscprintf(fmt, args);
	if (len < 0)
		return;
	char* msg = (char*)malloc(len + 1);
	if (!msg)
		return;
	if (vsnprintf(msg, len + 1, fmt, args) >= 0)
		BNLog(level, "%s", msg);
	free(msg);
#else
	char* msg;
	if (vasprintf(&msg, fmt, args) < 0)
		return;
	BNLog(level, "%s", msg);
	free(msg);
#endif
}


void BinaryNinja::Log(BNLogLevel level, const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(level, fmt, args);
	va_end(args);
}


void BinaryNinja::LogDebug(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(DebugLog, fmt, args);
	va_end(args);
}


void BinaryNinja::LogInfo(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(InfoLog, fmt, args);
	va_end(args);
}


void BinaryNinja::LogWarn(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(WarningLog, fmt, args);
	va_end(args);
}


void BinaryNinja::LogError(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(ErrorLog, fmt, args);
	va_end(args);
}


void BinaryNinja::LogAlert(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(AlertLog, fmt, args);
	va_end(args);
}


void BinaryNinja::LogToStdout(BNLogLevel minimumLevel)
{
	BNLogToStdout(minimumLevel);
}


void BinaryNinja::LogToStderr(BNLogLevel minimumLevel)
{
	BNLogToStderr(minimumLevel);
}


bool BinaryNinja::LogToFile(BNLogLevel minimumLevel, const string& path, bool append)
{
	return BNLogToFile(minimumLevel, path.c_str(), append);
}


void BinaryNinja::CloseLogs()
{
	BNCloseLogs();
}
