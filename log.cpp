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
#include <thread>
#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;

void LogListener::LogMessageCallback(void* ctxt, size_t session, BNLogLevel level, const char* msg, const char* logger_name, size_t tid)
{
	LogListener* listener = (LogListener*)ctxt;
	listener->LogMessage(session, level, msg, logger_name, tid);
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


static void PerformLog(size_t session, BNLogLevel level, const string& logger_name, size_t tid, const char* fmt, va_list args)
{
#if defined(_MSC_VER)
	int len = _vscprintf(fmt, args);
	if (len < 0)
		return;
	char* msg = (char*)malloc(len + 1);
	if (!msg)
		return;
	if (vsnprintf(msg, len + 1, fmt, args) >= 0)
		BNLog(session, level, logger_name.c_str(), tid, "%s", msg);
	free(msg);
#else
	char* msg;
	if (vasprintf(&msg, fmt, args) < 0)
		return;
	BNLog(session, level, logger_name.c_str(), tid, "%s", msg);
	free(msg);
#endif
}


void BinaryNinja::Log(BNLogLevel level, const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(0, level, "", 0, fmt, args);
	va_end(args);
}


void BinaryNinja::LogTrace(const char* fmt, ...)
{
#ifdef _DEBUG
	va_list args;
	va_start(args, fmt);
	PerformLog(0, DebugLog, "", 0, fmt, args);
	va_end(args);
#endif
}


void BinaryNinja::LogDebug(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(0, DebugLog, "", 0, fmt, args);
	va_end(args);
}


void BinaryNinja::LogInfo(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(0, InfoLog, "", 0, fmt, args);
	va_end(args);
}


void BinaryNinja::LogWarn(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(0, WarningLog, "", 0, fmt, args);
	va_end(args);
}


void BinaryNinja::LogError(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(0, ErrorLog, "", 0, fmt, args);
	va_end(args);
}


void BinaryNinja::LogAlert(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(0, AlertLog, "", 0, fmt, args);
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

size_t Logger::GetThreadId() const
{
	return std::hash<std::thread::id>{}(std::this_thread::get_id());
}

Logger::Logger(BNLogger* logger)
{
	m_object = logger;
}


Logger::Logger(const string& loggerName, size_t sessionId)
{
	m_object = BNLogCreateLogger(loggerName.c_str(), sessionId);
}


void Logger::Log(BNLogLevel level, const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(GetSessionId(), level, GetName(), GetThreadId(), fmt, args);
	va_end(args);
}


void Logger::LogTrace(const char* fmt, ...)
{
#ifdef _DEBUG
	va_list args;
	va_start(args, fmt);
	PerformLog(GetSessionId(), DebugLog, GetName(), GetThreadId(), fmt, args);
	va_end(args);
#endif
}


void Logger::LogDebug(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(GetSessionId(), DebugLog, GetName(), GetThreadId(), fmt, args);
	va_end(args);
}


void Logger::LogInfo(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(GetSessionId(), InfoLog, GetName(), GetThreadId(), fmt, args);
	va_end(args);
}


void Logger::LogWarn(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(GetSessionId(), WarningLog, GetName(), GetThreadId(), fmt, args);
	va_end(args);
}


void Logger::LogError(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(GetSessionId(), ErrorLog, GetName(), GetThreadId(), fmt, args);
	va_end(args);
}


void Logger::LogAlert(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(GetSessionId(), AlertLog, GetName(), GetThreadId(), fmt, args);
	va_end(args);
}


string Logger::GetName()
{
	char* name = BNLoggerGetName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


size_t Logger::GetSessionId()
{
	return BNLoggerGetSessionId(m_object);
}


Ref<Logger> LogRegistry::CreateLogger(const std::string& loggerName, size_t sessionId)
{
	return new Logger(BNLogCreateLogger(loggerName.c_str(), sessionId));
}


Ref<Logger> LogRegistry::GetLogger(const std::string& loggerName, size_t sessionId)
{
	return new Logger(BNLogGetLogger(loggerName.c_str(), sessionId));
}


vector<string> LogRegistry::GetLoggerNames()
{
	size_t count = 0;
	char** names = BNLogGetLoggerNames(&count);
	vector<string> result;
	result.reserve(count);
	for (size_t i = 0; i < count; ++i)
		result.push_back(names[i]);
	BNFreeStringList(names, count);
	return result;
}


struct RegisterLoggerCallbackContext
{
	std::function<void(const string&)> func;
};


static void RegisterLoggerCallbackHelper(const char* name, void* ctxt)
{
	RegisterLoggerCallbackContext* cb = (RegisterLoggerCallbackContext*)ctxt;
	cb->func(name);
}


void LogRegistry::RegisterLoggerCallback(const std::function<void(const string&)>& cb)
{
	// we leak this LoggerCallback but since you can't unregister them it doesn't really matter
	auto loggerCallback = new RegisterLoggerCallbackContext;
	loggerCallback->func = cb;
	BNLogRegisterLoggerCallback(RegisterLoggerCallbackHelper, loggerCallback);
}
