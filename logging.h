#pragma once

#include "binaryninjacore.h"
#include "fmt/core.h"
#include "refcount.h"
#include <string>
#include <unordered_map>
#include <vector>

namespace BinaryNinja
{

	/*!
		\ingroup logging
	*/
	class LogListener
	{
		static void LogMessageCallback(void* ctxt, size_t session, BNLogLevel level, const char* msg, const char* logger_name = "", size_t tid = 0);
		static void CloseLogCallback(void* ctxt);
		static BNLogLevel GetLogLevelCallback(void* ctxt);

	  public:
		virtual ~LogListener() {}

		static void RegisterLogListener(LogListener* listener);
		static void UnregisterLogListener(LogListener* listener);
		static void UpdateLogListeners();

		virtual void LogMessage(size_t session, BNLogLevel level, const std::string& msg, const std::string& logger_name = "", size_t tid = 0) = 0;
		virtual void CloseLog() {}
		virtual BNLogLevel GetLogLevel() { return WarningLog; }
	};

	class Architecture;
	class BackgroundTask;
	class Platform;
	class Settings;
	class Workflow;
	class Type;
	class DataBuffer;
	class MainThreadAction;
	class MainThreadActionHandler;
	class InteractionHandler;
	class QualifiedName;
	class FlowGraph;
	class ReportCollection;
	struct FormInputField;

	/*! Logs to the error console with the given BNLogLevel.

	    @threadsafe

	    \ingroup logging

	    \param level BNLogLevel debug log level
	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
	BN_PRINTF_ATTRIBUTE(2, 3)
	void Log(BNLogLevel level, const char* fmt, ...);

	/*! LogTrace only writes text to the error console if the console is set to log level: DebugLog
	    Log level and the build is not a DEBUG build (i.e. the preprocessor directive _DEBUG is defined)

	    @threadsafe

	    \ingroup logging

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
	BN_PRINTF_ATTRIBUTE(1, 2)
	void LogTrace(const char* fmt, ...);


	/*! LogDebug only writes text to the error console if the console is set to log level: DebugLog
	    Log level DebugLog is the most verbose logging level in release builds.

	    @threadsafe

	    \ingroup logging

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
	BN_PRINTF_ATTRIBUTE(1, 2)
	void LogDebug(const char* fmt, ...);

	/*! LogInfo always writes text to the error console, and corresponds to the log level: InfoLog.
	    Log level InfoLog is the second most verbose logging level.

	    @threadsafe

	    \ingroup logging

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
	BN_PRINTF_ATTRIBUTE(1, 2)
	void LogInfo(const char* fmt, ...);

	/*! LogWarn writes text to the error console including a warning icon,
	    and also shows a warning icon in the bottom pane. LogWarn corresponds to the log level: WarningLog.

	    @threadsafe

	    \ingroup logging

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
	BN_PRINTF_ATTRIBUTE(1, 2)
	void LogWarn(const char* fmt, ...);

	/*! LogError writes text to the error console and pops up the error console. Additionally,
	    Errors in the console log include a error icon. LogError corresponds to the log level: ErrorLog.

	    @threadsafe

	    \ingroup logging

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
	BN_PRINTF_ATTRIBUTE(1, 2)
	void LogError(const char* fmt, ...);

	/*! LogAlert pops up a message box displaying the alert message and logs to the error console.
	    LogAlert corresponds to the log level: AlertLog.

	    @threadsafe

	    \ingroup logging

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
	BN_PRINTF_ATTRIBUTE(1, 2)
	void LogAlert(const char* fmt, ...);

	// Implementation detail
	void LogFV(BNLogLevel level, fmt::string_view format, fmt::format_args args);
	void LogTraceFV(fmt::string_view format, fmt::format_args args);
	void LogDebugFV(fmt::string_view format, fmt::format_args args);
	void LogInfoFV(fmt::string_view format, fmt::format_args args);
	void LogWarnFV(fmt::string_view format, fmt::format_args args);
	void LogErrorFV(fmt::string_view format, fmt::format_args args);
	void LogAlertFV(fmt::string_view format, fmt::format_args args);

	/*! Logs to the error console with the given BNLogLevel.

		@threadsafe

		\ingroup logging

		\param level BNLogLevel debug log level
		\param format fmt-style format string.
		\param ... Variable arguments corresponding to the format string.
	*/
	template<typename... T>
	void LogF(BNLogLevel level, fmt::format_string<T...> format, T&&... args)
	{
		LogFV(level, format, fmt::make_format_args(args...));
	}

	/*! LogTrace only writes text to the error console if the console is set to log level: DebugLog
		Log level and the build is not a DEBUG build (i.e. the preprocessor directive _DEBUG is defined)

		@threadsafe

		\ingroup logging

		\param format fmt-style format string.
		\param ... Variable arguments corresponding to the format string.
	*/
	template<typename... T>
	void LogTraceF(fmt::format_string<T...> format, T&&... args)
	{
		LogTraceFV(format, fmt::make_format_args(args...));
	}

	/*! LogDebug only writes text to the error console if the console is set to log level: DebugLog
		Log level DebugLog is the most verbose logging level in release builds.

		@threadsafe

		\ingroup logging

		\param format fmt-style format string.
		\param ... Variable arguments corresponding to the format string.
	*/
	template<typename... T>
	void LogDebugF(fmt::format_string<T...> format, T&&... args)
	{
		LogDebugFV(format, fmt::make_format_args(args...));
	}

	/*! LogInfo always writes text to the error console, and corresponds to the log level: InfoLog.
		Log level InfoLog is the second most verbose logging level.

		@threadsafe

		\ingroup logging

		\param format fmt-style format string.
		\param ... Variable arguments corresponding to the format string.
	*/
	template<typename... T>
	void LogInfoF(fmt::format_string<T...> format, T&&... args)
	{
		LogInfoFV(format, fmt::make_format_args(args...));
	}

	/*! LogWarn writes text to the error console including a warning icon,
		and also shows a warning icon in the bottom pane. LogWarn corresponds to the log level: WarningLog.

		@threadsafe

		\ingroup logging

		\param format fmt-style format string.
		\param ... Variable arguments corresponding to the format string.
	*/
	template<typename... T>
	void LogWarnF(fmt::format_string<T...> format, T&&... args)
	{
		LogWarnFV(format, fmt::make_format_args(args...));
	}

	/*! LogError writes text to the error console and pops up the error console. Additionally,
		Errors in the console log include a error icon. LogError corresponds to the log level: ErrorLog.

		@threadsafe

		\ingroup logging

		\param format fmt-style format string.
		\param ... Variable arguments corresponding to the format string.
	*/
	template<typename... T>
	void LogErrorF(fmt::format_string<T...> format, T&&... args)
	{
		LogErrorFV(format, fmt::make_format_args(args...));
	}

	/*! LogAlert pops up a message box displaying the alert message and logs to the error console.
		LogAlert corresponds to the log level: AlertLog.

		@threadsafe

		\ingroup logging

		\param format fmt-style format string.
		\param ... Variable arguments corresponding to the format string.
	*/
	template<typename... T>
	void LogAlertF(fmt::format_string<T...> format, T&&... args)
	{
		LogAlertFV(format, fmt::make_format_args(args...));
	}

	/*! Redirects the minimum level passed to standard out

	    @threadsafe

	    \ingroup logging

		\param minimumLevel minimum level to log to stdout
	*/
	void LogToStdout(BNLogLevel minimumLevel);

	/*! Redirects the minimum level passed to standard error

	    @threadsafe

	    \ingroup logging

		\param minimumLevel minimum level to log to stderr
	*/
	void LogToStderr(BNLogLevel minimumLevel);

	/*! Redirects minimum log level to the file at `path`, optionally appending rather than overwriting.

	    @threadsafe

	    \ingroup logging

		\param minimumLevel minimum level to log to stderr
		\param path Path to log to
		\param append Optional flag for specifying appending. True = append, False = overwrite.
	*/
	bool LogToFile(BNLogLevel minimumLevel, const std::string& path, bool append = false);

	/*! Close all log files

	    \ingroup logging
	*/
	void CloseLogs();

	class FileMetadata;
	class BinaryView;
	/*! Logger is a class allowing scoped logging to the console

		\ingroup logging
	*/
	class Logger: public CoreRefCountObject<BNLogger, BNNewLoggerReference, BNFreeLogger>
	{
			size_t GetThreadId() const;
			std::unordered_map<BNLogLevel, std::string> m_iterBuffer;
			friend struct Iterator;

			void LogFV(BNLogLevel level, fmt::string_view format, fmt::format_args args);
			void LogTraceFV(fmt::string_view format, fmt::format_args args);
			void LogDebugFV(fmt::string_view format, fmt::format_args args);
			void LogInfoFV(fmt::string_view format, fmt::format_args args);
			void LogWarnFV(fmt::string_view format, fmt::format_args args);
			void LogErrorFV(fmt::string_view format, fmt::format_args args);
			void LogAlertFV(fmt::string_view format, fmt::format_args args);

		public:
			Logger(BNLogger* logger);

			/*! Create a logger with the specified name and session ID

				\warning You may want to use LogRegistry::CreateLogger and LogRegistry::GetLogger instead of this. If
			 			 you already have access to a BinaryView, you may want to use bv->CreateLogger() instead of this.

				\see BinaryView::CreateLogger()

			 	\code{.cpp}
			 	auto logger = Logger("MyPluginName", 0);
			 	\endcode

			 	Session ID corresponds to the tab for the specified BinaryView, and the default of 0 will log to *all tabs*.

			 	\see FileMetadata::GetSessionId()

				\param loggerName Name of the logger to create
				\param sessionId Session ID for the logger.
			*/
			Logger(const std::string& loggerName, size_t sessionId = 0);

			/*! Logs to the error console with the given BNLogLevel.

	    			@threadsafe

				\param level BNLogLevel debug log level
	    		\param fmt C-style format string.
	    		\param ... Variable arguments corresponding to the format string.
			*/
			void Log(BNLogLevel level, const char* fmt, ...);

			/*! LogTrace only writes text to the error console if the console is set to log level: DebugLog
				Log level and the build is not a DEBUG build (i.e. the preprocessor directive _DEBUG is defined)

	    			@threadsafe

				\param fmt C-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			void LogTrace(const char* fmt, ...);

			/*! LogDebug only writes text to the error console if the console is set to log level: DebugLog
				Log level DebugLog is the most verbose logging level in release builds.

	    			@threadsafe

				\param fmt C-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			void LogDebug(const char* fmt, ...);

			/*! LogInfo always writes text to the error console, and corresponds to the log level: InfoLog.
				Log level InfoLog is the second most verbose logging level.

	    			@threadsafe

				\param fmt C-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			void LogInfo(const char* fmt, ...);

			/*! LogWarn writes text to the error console including a warning icon,
				and also shows a warning icon in the bottom pane. LogWarn corresponds to the log level: WarningLog.

	    			@threadsafe

				\param fmt C-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			void LogWarn(const char* fmt, ...);

			/*! LogError writes text to the error console and pops up the error console. Additionally,
				Errors in the console log include a error icon. LogError corresponds to the log level: ErrorLog.

	    			@threadsafe

				\param fmt C-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			void LogError(const char* fmt, ...);

			/*! LogAlert pops up a message box displaying the alert message and logs to the error console.
				LogAlert corresponds to the log level: AlertLog.

	    			@threadsafe

				\param fmt C-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			void LogAlert(const char* fmt, ...);

			/*! Logs to the error console with the given BNLogLevel.

					@threadsafe

				\param level BNLogLevel debug log level
				\param format fmt-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			template<typename... T>
			void LogF(BNLogLevel level, fmt::format_string<T...> format, T&&... args)
			{
				LogFV(level, format, fmt::make_format_args(args...));
			}

			/*! LogTrace only writes text to the error console if the console is set to log level: DebugLog
				Log level and the build is not a DEBUG build (i.e. the preprocessor directive _DEBUG is defined)

					@threadsafe

				\param format fmt-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			template<typename... T>
			void LogTraceF(fmt::format_string<T...> format, T&&... args)
			{
				LogTraceFV(format, fmt::make_format_args(args...));
			}

			/*! LogDebug only writes text to the error console if the console is set to log level: DebugLog
				Log level DebugLog is the most verbose logging level in release builds.

					@threadsafe

				\param format fmt-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			template<typename... T>
			void LogDebugF(fmt::format_string<T...> format, T&&... args)
			{
				LogDebugFV(format, fmt::make_format_args(args...));
			}

			/*! LogInfo always writes text to the error console, and corresponds to the log level: InfoLog.
				Log level InfoLog is the second most verbose logging level.

					@threadsafe

				\param format fmt-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			template<typename... T>
			void LogInfoF(fmt::format_string<T...> format, T&&... args)
			{
				LogInfoFV(format, fmt::make_format_args(args...));
			}

			/*! LogWarn writes text to the error console including a warning icon,
				and also shows a warning icon in the bottom pane. LogWarn corresponds to the log level: WarningLog.

					@threadsafe

				\param format fmt-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			template<typename... T>
			void LogWarnF(fmt::format_string<T...> format, T&&... args)
			{
				LogWarnFV(format, fmt::make_format_args(args...));
			}

			/*! LogError writes text to the error console and pops up the error console. Additionally,
				Errors in the console log include a error icon. LogError corresponds to the log level: ErrorLog.

					@threadsafe

				\param format fmt-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			template<typename... T>
			void LogErrorF(fmt::format_string<T...> format, T&&... args)
			{
				LogErrorFV(format, fmt::make_format_args(args...));
			}

			/*! LogAlert pops up a message box displaying the alert message and logs to the error console.
				LogAlert corresponds to the log level: AlertLog.

					@threadsafe

				\param format fmt-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			template<typename... T>
			void LogAlertF(fmt::format_string<T...> format, T&&... args)
			{
				LogAlertFV(format, fmt::make_format_args(args...));
			}

			/*! Get the name registered for this Logger

	    			@threadsafe

				\return The logger name
			*/
			std::string GetName();

			/*! Get the session ID registered for this logger

	    			@threadsafe

				\return The logger session ID
			*/
			size_t GetSessionId();
	};

	/*! A class allowing registering and retrieving Loggers

		\see BinaryView::CreateLogger

	 	\ingroup logging
	*/
	class LogRegistry
	{
	public:
		/*! Create a logger with the specified name and session ID

	    		@threadsafe

			\note If you already have a BinaryView, you may want to use \c BinaryView::CreateLogger instead of this.

			\code{.cpp}
			auto sessionID = bv->GetFile()->GetSessionId();
			auto logger = LogRegistry::CreateLogger("MyPluginName", sessionID);
			\endcode

			Session ID corresponds to the tab for the specified BinaryView, and the default of 0 will log to *all tabs*.

		 	\see FileMetadata::GetSessionId()

			\param loggerName Name of the logger to create
			\param sessionId Session ID for the logger
		 	\return The created logger
		*/
		static Ref<Logger> CreateLogger(const std::string& loggerName, size_t sessionId = 0);

		/*! Get a logger with the specified name and session ID

	    		@threadsafe

			\code{.cpp}
			auto sessionID = bv->GetFile()->GetSessionId();
			auto logger = LogRegistry::GetLogger("MyPluginName", sessionID);
			\endcode

			Session ID corresponds to the tab for the specified BinaryView, and the default of 0 will log to *all tabs*.

		 	\see FileMetadata::GetSessionId()

			\param loggerName Name of the logger to create
			\param sessionId Session ID for the logger
		 	\return The created logger
		*/
		static Ref<Logger> GetLogger(const std::string& loggerName, size_t sessionId = 0);

		/*! Get the list of registered Logger names

	    		@threadsafe

			\return a list of registered logger names
		*/
		static std::vector<std::string> GetLoggerNames();
	};

}
