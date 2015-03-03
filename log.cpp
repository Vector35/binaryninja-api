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


void LogListener::RegisterLogListener(LogListener* listener)
{
	BNLogListener callbacks;
	callbacks.context = listener;
	callbacks.log = LogMessageCallback;
	callbacks.close = CloseLogCallback;
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


static void PerformLog(BNLogLevel level, const char* fmt, va_list args)
{
#if defined(_MSC_VER)
	int len = _vscprintf(fmt, args);
	if (len < 0)
		return;
	char* msg = malloc(len + 1);
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
}


void BinaryNinja::LogDebug(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(DebugLog, fmt, args);
}


void BinaryNinja::LogInfo(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(InfoLog, fmt, args);
}


void BinaryNinja::LogWarn(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(WarningLog, fmt, args);
}


void BinaryNinja::LogError(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(ErrorLog, fmt, args);
}


void BinaryNinja::LogAlert(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	PerformLog(AlertLog, fmt, args);
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
