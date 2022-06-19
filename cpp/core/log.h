#pragma once
#include "core/binaryninja_defs.h"

extern "C"
{
	struct BNLogger;

	//! Console log levels
	enum BNLogLevel
	{
		DebugLog = 0,    //! Debug logging level, most verbose logging level
		InfoLog = 1,     //! Information logging level, default logging level
		WarningLog = 2,  //! Warning logging level, messages show with warning icon in the UI
		ErrorLog = 3,    //! Error logging level, messages show with error icon in the UI
		AlertLog = 4     //! Alert logging level, messages are displayed with popup message box in the UI
	};

	// Callbacks
	struct BNLogListener
	{
		void* context;
		void (*log)(void* ctxt, size_t sessionId, BNLogLevel level, const char* msg, const char* logger_name, size_t tid);
		void (*close)(void* ctxt);
		BNLogLevel (*getLogLevel)(void* ctxt);
	};

	// Logging
#ifdef __GNUC__
	__attribute__((format(printf, 5, 6)))
#endif
	BINARYNINJACOREAPI void
	    BNLog(size_t session, BNLogLevel level, const char* logger_name, size_t tid, const char* fmt, ...);

#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)))
#endif
	BINARYNINJACOREAPI void
	    BNLogDebug(const char* fmt, ...);

#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)))
#endif
	BINARYNINJACOREAPI void
	    BNLogInfo(const char* fmt, ...);

#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)))
#endif
	BINARYNINJACOREAPI void
	    BNLogWarn(const char* fmt, ...);

#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)))
#endif
	BINARYNINJACOREAPI void
	    BNLogError(const char* fmt, ...);

#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)))
#endif
	BINARYNINJACOREAPI void
	    BNLogAlert(const char* fmt, ...);

	BINARYNINJACOREAPI void BNLogString(size_t session, BNLogLevel level, const char* logger_name, size_t tid, const char* str);

	BINARYNINJACOREAPI BNLogger* BNNewLoggerReference(BNLogger* logger);
	BINARYNINJACOREAPI void BNFreeLogger(BNLogger* logger);

#ifdef __GNUC__
	__attribute__((format(printf, 3, 4)))
#endif
	BINARYNINJACOREAPI void BNLoggerLog(BNLogger* logger, BNLogLevel level, const char* fmt, ...);
	BINARYNINJACOREAPI void BNLoggerLogString(BNLogger* logger, BNLogLevel level, const char* msg);

	BINARYNINJACOREAPI char* BNLoggerGetName(BNLogger* logger);
	BINARYNINJACOREAPI size_t BNLoggerGetSessionId(BNLogger* logger);
	BINARYNINJACOREAPI BNLogger* BNLogCreateLogger(const char* loggerName, size_t sessionId);
	BINARYNINJACOREAPI BNLogger* BNLogGetLogger(const char* loggerName, size_t sessionId);
	BINARYNINJACOREAPI char** BNLogGetLoggerNames(size_t* count);
	BINARYNINJACOREAPI void BNLogRegisterLoggerCallback(void (*cb)(const char* name, void* ctxt), void* ctxt);

	BINARYNINJACOREAPI void BNRegisterLogListener(BNLogListener* listener);
	BINARYNINJACOREAPI void BNUnregisterLogListener(BNLogListener* listener);
	BINARYNINJACOREAPI void BNUpdateLogListeners(void);

	BINARYNINJACOREAPI void BNLogToStdout(BNLogLevel minimumLevel);
	BINARYNINJACOREAPI void BNLogToStderr(BNLogLevel minimumLevel);
	BINARYNINJACOREAPI bool BNLogToFile(BNLogLevel minimumLevel, const char* path, bool append);
	BINARYNINJACOREAPI void BNCloseLogs(void);
}