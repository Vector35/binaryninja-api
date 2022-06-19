#pragma once
#include <string>
#include "core/log.h"
#include "refcount.hpp"

namespace BinaryNinja {

	class LogListener
	{
		static void LogMessageCallback(void* ctxt, size_t session, BNLogLevel level, const char* msg, const char* logger_name = "", size_t tid = 0);
		static void CloseLogCallback(void* ctxt);
		static BNLogLevel GetLogLevelCallback(void* ctxt);

	  public:
		virtual ~LogListener();

		static void RegisterLogListener(LogListener* listener);
		static void UnregisterLogListener(LogListener* listener);
		static void UpdateLogListeners();

		virtual void LogMessage(size_t session, BNLogLevel level, const std::string& msg, const std::string& logger_name = "", size_t tid = 0) = 0;
		virtual void CloseLog();
		virtual BNLogLevel GetLogLevel();
	};

	class Logger: public CoreRefCountObject<BNLogger, BNNewLoggerReference, BNFreeLogger>
	{
			size_t GetThreadId() const;
		public:
			Logger(BNLogger* logger);
			Logger(const std::string& loggerName, size_t sessionId = 0);
			void Log(BNLogLevel level, const char* fmt, ...);
			void LogTrace(const char* fmt, ...);
			void LogDebug(const char* fmt, ...);
			void LogInfo(const char* fmt, ...);
			void LogWarn(const char* fmt, ...);
			void LogError(const char* fmt, ...);
			void LogAlert(const char* fmt, ...);
			std::string GetName();
			size_t GetSessionId();
	};

	class LogRegistry
	{
	public:
		static Ref<Logger> CreateLogger(const std::string& loggerName, size_t sessionId = 0);
		static Ref<Logger> GetLogger(const std::string& loggerName, size_t sessionId = 0);
		static std::vector<std::string> GetLoggerNames();
		static void RegisterLoggerCallback(const std::function<void(const std::string&)>& cb);
	};

	/*! Logs to the error console with the given BNLogLevel.

	    \param level BNLogLevel debug log level
	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	 */
#ifdef __GNUC__
	__attribute__((format(printf, 2, 3)))
#endif
	void Log(BNLogLevel level, const char* fmt, ...);

	/*! LogTrace only writes text to the error console if the console is set to log level: DebugLog
	    Log level and the build is not a DEBUG build (i.e. the preprocessor directive _DEBUG is defined)

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	 */
#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)))
#endif
	void LogTrace(const char* fmt, ...);


	/*! LogDebug only writes text to the error console if the console is set to log level: DebugLog
	    Log level DebugLog is the most verbose logging level in release builds.

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	 */
#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)))
#endif
	void LogDebug(const char* fmt, ...);

	/*! LogInfo always writes text to the error console, and corresponds to the log level: InfoLog.
	    Log level InfoLog is the second most verbose logging level.

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	 */
#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)))
#endif
	void LogInfo(const char* fmt, ...);

	/*! LogWarn writes text to the error console including a warning icon,
	    and also shows a warning icon in the bottom pane. LogWarn corresponds to the log level: WarningLog.

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	 */
#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)))
#endif
	void LogWarn(const char* fmt, ...);

	/*! LogError writes text to the error console and pops up the error console. Additionall,
	    Errors in the console log include a error icon. LogError corresponds to the log level: ErrorLog.

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	 */
#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)))
#endif
	void LogError(const char* fmt, ...);

	/*! LogAlert pops up a message box displaying the alert message and logs to the error console.
	    LogAlert corresponds to the log level: AlertLog.

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	 */
#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)))
#endif
	void LogAlert(const char* fmt, ...);

	void LogToStdout(BNLogLevel minimumLevel);
	void LogToStderr(BNLogLevel minimumLevel);
	bool LogToFile(BNLogLevel minimumLevel, const std::string& path, bool append = false);
	void CloseLogs();
}