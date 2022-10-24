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

#pragma once
#ifdef WIN32
	#define NOMINMAX
	#include <windows.h>
#endif
#include <stddef.h>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <exception>
#include <functional>
#include <set>
#include <mutex>
#include <atomic>
#include <memory>
#include <cstdint>
#include <type_traits>
#include <variant>
#include <optional>
#include <memory>
#include "binaryninjacore.h"
#include "json/json.h"

#ifdef _MSC_VER
	#define NOEXCEPT
#else
	#define NOEXCEPT noexcept
#endif

//#define BN_REF_COUNT_DEBUG  // Mac OS X only, prints stack trace of leaked references

#ifdef DOXYGEN_INCLUDE_MAINPAGE
#include ".doxygen.h"
#endif

namespace BinaryNinja {
	/*!
		\ingroup refcount
	*/
	class RefCountObject
	{
	  public:
		std::atomic<int> m_refs;
		RefCountObject() : m_refs(0) {}
		virtual ~RefCountObject() {}

		RefCountObject* GetObject() { return this; }
		static RefCountObject* GetObject(RefCountObject* obj) { return obj; }

		void AddRef() { m_refs.fetch_add(1); }

		void Release()
		{
			if (m_refs.fetch_sub(1) == 1)
				delete this;
		}
	};


	/*!
		\ingroup refcount
	*/
	template <class T, T* (*AddObjectReference)(T*), void (*FreeObjectReference)(T*)>
	class CoreRefCountObject
	{
		void AddRefInternal() { m_refs.fetch_add(1); }

		void ReleaseInternal()
		{
			if (m_refs.fetch_sub(1) == 1)
			{
				if (!m_registeredRef)
					delete this;
			}
		}

	  public:
		std::atomic<int> m_refs;
		bool m_registeredRef = false;
		T* m_object;
		CoreRefCountObject() : m_refs(0), m_object(nullptr) {}
		virtual ~CoreRefCountObject() {}

		T* GetObject() const { return m_object; }

		static T* GetObject(CoreRefCountObject* obj)
		{
			if (!obj)
				return nullptr;
			return obj->GetObject();
		}

		// This is needed by code like
		// bool operator==(const T* obj) const { return T::GetObject(m_obj) == T::GetObject(obj); }
		static T* GetObject(const CoreRefCountObject* obj)
		{
			if (!obj)
				return nullptr;
			return obj->GetObject();
		}

		void AddRef()
		{
			if (m_object && (m_refs != 0))
				AddObjectReference(m_object);
			AddRefInternal();
		}

		void Release()
		{
			if (m_object)
				FreeObjectReference(m_object);
			ReleaseInternal();
		}

		void AddRefForRegistration() { m_registeredRef = true; }

		void ReleaseForRegistration()
		{
			m_object = nullptr;
			m_registeredRef = false;
			if (m_refs == 0)
				delete this;
		}
	};

	/*!
		\ingroup refcount
	*/
	template <class T>
	class StaticCoreRefCountObject
	{
		void AddRefInternal() { m_refs.fetch_add(1); }

		void ReleaseInternal()
		{
			if (m_refs.fetch_sub(1) == 1)
				delete this;
		}

	  public:
		std::atomic<int> m_refs;
		T* m_object;
		StaticCoreRefCountObject() : m_refs(0), m_object(nullptr) {}
		virtual ~StaticCoreRefCountObject() {}

		T* GetObject() const { return m_object; }

		static T* GetObject(StaticCoreRefCountObject* obj)
		{
			if (!obj)
				return nullptr;
			return obj->GetObject();
		}

		void AddRef() { AddRefInternal(); }

		void Release() { ReleaseInternal(); }

		void AddRefForRegistration() { AddRefInternal(); }
	};

	/*!
		\ingroup refcount
	*/
	template <class T>
	class Ref
	{
		T* m_obj;
#ifdef BN_REF_COUNT_DEBUG
		void* m_assignmentTrace = nullptr;
#endif

	  public:
		Ref<T>() : m_obj(NULL) {}

		Ref<T>(T* obj) : m_obj(obj)
		{
			if (m_obj)
			{
				m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			}
		}

		Ref<T>(const Ref<T>& obj) : m_obj(obj.m_obj)
		{
			if (m_obj)
			{
				m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			}
		}

		Ref<T>(Ref<T>&& other) : m_obj(other.m_obj)
		{
			other.m_obj = 0;
#ifdef BN_REF_COUNT_DEBUG
			m_assignmentTrace = other.m_assignmentTrace;
#endif
		}

		~Ref<T>()
		{
			if (m_obj)
			{
				m_obj->Release();
#ifdef BN_REF_COUNT_DEBUG
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
#endif
			}
		}

		Ref<T>& operator=(const Ref<T>& obj)
		{
#ifdef BN_REF_COUNT_DEBUG
			if (m_obj)
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
			if (obj.m_obj)
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			T* oldObj = m_obj;
			m_obj = obj.m_obj;
			if (m_obj)
				m_obj->AddRef();
			if (oldObj)
				oldObj->Release();
			return *this;
		}

		Ref<T>& operator=(Ref<T>&& other)
		{
			if (m_obj)
			{
#ifdef BN_REF_COUNT_DEBUG
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
#endif
				m_obj->Release();
			}
			m_obj = other.m_obj;
			other.m_obj = 0;
#ifdef BN_REF_COUNT_DEBUG
			m_assignmentTrace = other.m_assignmentTrace;
#endif
			return *this;
		}

		Ref<T>& operator=(T* obj)
		{
#ifdef BN_REF_COUNT_DEBUG
			if (m_obj)
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
			if (obj)
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			T* oldObj = m_obj;
			m_obj = obj;
			if (m_obj)
				m_obj->AddRef();
			if (oldObj)
				oldObj->Release();
			return *this;
		}

		operator T*() const { return m_obj; }

		T* operator->() const { return m_obj; }

		T& operator*() const { return *m_obj; }

		bool operator!() const { return m_obj == NULL; }

		bool operator==(const T* obj) const { return T::GetObject(m_obj) == T::GetObject(obj); }

		bool operator==(const Ref<T>& obj) const { return T::GetObject(m_obj) == T::GetObject(obj.m_obj); }

		bool operator!=(const T* obj) const { return T::GetObject(m_obj) != T::GetObject(obj); }

		bool operator!=(const Ref<T>& obj) const { return T::GetObject(m_obj) != T::GetObject(obj.m_obj); }

		bool operator<(const T* obj) const { return T::GetObject(m_obj) < T::GetObject(obj); }

		bool operator<(const Ref<T>& obj) const { return T::GetObject(m_obj) < T::GetObject(obj.m_obj); }

		T* GetPtr() const { return m_obj; }
	};


	/*!
		\ingroup confidence
	*/
	class ConfidenceBase
	{
	  protected:
		uint8_t m_confidence;

	  public:
		ConfidenceBase() : m_confidence(0) {}

		ConfidenceBase(uint8_t conf) : m_confidence(conf) {}

		static uint8_t Combine(uint8_t a, uint8_t b)
		{
			uint8_t result = (uint8_t)(((uint32_t)a * (uint32_t)b) / BN_FULL_CONFIDENCE);
			if ((a >= BN_MINIMUM_CONFIDENCE) && (b >= BN_MINIMUM_CONFIDENCE) && (result < BN_MINIMUM_CONFIDENCE))
				result = BN_MINIMUM_CONFIDENCE;
			return result;
		}

		uint8_t GetConfidence() const { return m_confidence; }
		uint8_t GetCombinedConfidence(uint8_t base) const { return Combine(m_confidence, base); }
		void SetConfidence(uint8_t conf) { m_confidence = conf; }
		bool IsUnknown() const { return m_confidence == 0; }
	};

	/*!
		\ingroup confidence
	*/
	template <class T>
	class Confidence : public ConfidenceBase
	{
		T m_value;

	  public:
		Confidence() {}

		Confidence(const T& value) : ConfidenceBase(BN_FULL_CONFIDENCE), m_value(value) {}

		Confidence(const T& value, uint8_t conf) : ConfidenceBase(conf), m_value(value) {}

		Confidence(const Confidence<T>& v) : ConfidenceBase(v.m_confidence), m_value(v.m_value) {}

		operator T() const { return m_value; }
		T* operator->() { return &m_value; }
		const T* operator->() const { return &m_value; }

		// This MUST be a copy. There are subtle compiler scoping bugs that will cause nondeterministic failures
		// when using one of these objects as a temporary if a reference is returned here. Unfortunately, this has
		// negative performance implications. Make a local copy first if the template argument is a complex
		// object and it is needed repeatedly.
		T GetValue() const { return m_value; }

		void SetValue(const T& value) { m_value = value; }

		Confidence<T>& operator=(const Confidence<T>& v)
		{
			m_value = v.m_value;
			m_confidence = v.m_confidence;
			return *this;
		}

		Confidence<T>& operator=(const T& value)
		{
			m_value = value;
			m_confidence = BN_FULL_CONFIDENCE;
			return *this;
		}

		bool operator<(const Confidence<T>& a) const
		{
			if (m_value < a.m_value)
				return true;
			if (a.m_value < m_value)
				return false;
			return m_confidence < a.m_confidence;
		}

		bool operator==(const Confidence<T>& a) const
		{
			if (m_confidence != a.m_confidence)
				return false;
			return m_confidence == a.m_confidence;
		}

		bool operator!=(const Confidence<T>& a) const { return !(*this == a); }
	};

	/*!
		\ingroup confidence
	*/
	template <class T>
	class Confidence<Ref<T>> : public ConfidenceBase
	{
		Ref<T> m_value;

	  public:
		Confidence() {}

		Confidence(T* value) : ConfidenceBase(value ? BN_FULL_CONFIDENCE : 0), m_value(value) {}

		Confidence(T* value, uint8_t conf) : ConfidenceBase(conf), m_value(value) {}

		Confidence(const Ref<T>& value) : ConfidenceBase(value ? BN_FULL_CONFIDENCE : 0), m_value(value) {}

		Confidence(const Ref<T>& value, uint8_t conf) : ConfidenceBase(conf), m_value(value) {}

		Confidence(const Confidence<Ref<T>>& v) : ConfidenceBase(v.m_confidence), m_value(v.m_value) {}

		operator Ref<T>() const { return m_value; }
		operator T*() const { return m_value.GetPtr(); }
		T* operator->() const { return m_value.GetPtr(); }
		bool operator!() const { return !m_value; }

		const Ref<T>& GetValue() const { return m_value; }
		void SetValue(T* value) { m_value = value; }
		void SetValue(const Ref<T>& value) { m_value = value; }

		Confidence<Ref<T>>& operator=(const Confidence<Ref<T>>& v)
		{
			m_value = v.m_value;
			m_confidence = v.m_confidence;
			return *this;
		}

		Confidence<Ref<T>>& operator=(T* value)
		{
			m_value = value;
			m_confidence = value ? BN_FULL_CONFIDENCE : 0;
			return *this;
		}

		Confidence<Ref<T>>& operator=(const Ref<T>& value)
		{
			m_value = value;
			m_confidence = value ? BN_FULL_CONFIDENCE : 0;
			return *this;
		}

		bool operator<(const Confidence<Ref<T>>& a) const
		{
			if (m_value < a.m_value)
				return true;
			if (a.m_value < m_value)
				return false;
			return m_confidence < a.m_confidence;
		}

		bool operator==(const Confidence<Ref<T>>& a) const
		{
			if (m_confidence != a.m_confidence)
				return false;
			return m_confidence == a.m_confidence;
		}

		bool operator!=(const Confidence<Ref<T>>& a) const { return !(*this == a); }
	};

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

	    \ingroup logging

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

	    \ingroup logging

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)))
#endif
	void LogTrace(const char* fmt, ...);


	/*! LogDebug only writes text to the error console if the console is set to log level: DebugLog
	    Log level DebugLog is the most verbose logging level in release builds.

	    \ingroup logging

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)))
#endif
	void LogDebug(const char* fmt, ...);

	/*! LogInfo always writes text to the error console, and corresponds to the log level: InfoLog.
	    Log level InfoLog is the second most verbose logging level.

	    \ingroup logging

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)))
#endif
	void LogInfo(const char* fmt, ...);

	/*! LogWarn writes text to the error console including a warning icon,
	    and also shows a warning icon in the bottom pane. LogWarn corresponds to the log level: WarningLog.

	    \ingroup logging

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)))
#endif
	void LogWarn(const char* fmt, ...);

	/*! LogError writes text to the error console and pops up the error console. Additionall,
	    Errors in the console log include a error icon. LogError corresponds to the log level: ErrorLog.

	    \ingroup logging

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)))
#endif
	void LogError(const char* fmt, ...);

	/*! LogAlert pops up a message box displaying the alert message and logs to the error console.
	    LogAlert corresponds to the log level: AlertLog.

	    \ingroup logging

	    \param fmt C-style format string.
	    \param ... Variable arguments corresponding to the format string.
	*/
#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)))
#endif
	void LogAlert(const char* fmt, ...);

	/*! Redirects the minimum level passed to standard out

	    \ingroup logging

		\param minimumLevel minimum level to log to stdout
	*/
	void LogToStdout(BNLogLevel minimumLevel);

	/*! Redirects the minimum level passed to standard error

	    \ingroup logging

		\param minimumLevel minimum level to log to stderr
	*/
	void LogToStderr(BNLogLevel minimumLevel);

	/*! Redirects minimum log level to the file at `path`, optionally appending rather than overwriting.

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

				\param level BNLogLevel debug log level
	    		\param fmt C-style format string.
	    		\param ... Variable arguments corresponding to the format string.
			*/
			void Log(BNLogLevel level, const char* fmt, ...);

			/*! LogTrace only writes text to the error console if the console is set to log level: DebugLog
				Log level and the build is not a DEBUG build (i.e. the preprocessor directive _DEBUG is defined)

				\param fmt C-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			void LogTrace(const char* fmt, ...);

			/*! LogDebug only writes text to the error console if the console is set to log level: DebugLog
				Log level DebugLog is the most verbose logging level in release builds.

				\param fmt C-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			void LogDebug(const char* fmt, ...);

			/*! LogInfo always writes text to the error console, and corresponds to the log level: InfoLog.
				Log level InfoLog is the second most verbose logging level.

				\param fmt C-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			void LogInfo(const char* fmt, ...);

			/*! LogWarn writes text to the error console including a warning icon,
				and also shows a warning icon in the bottom pane. LogWarn corresponds to the log level: WarningLog.

				\param fmt C-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			void LogWarn(const char* fmt, ...);

			/*! LogError writes text to the error console and pops up the error console. Additionally,
				Errors in the console log include a error icon. LogError corresponds to the log level: ErrorLog.

				\param fmt C-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			void LogError(const char* fmt, ...);

			/*! LogAlert pops up a message box displaying the alert message and logs to the error console.
				LogAlert corresponds to the log level: AlertLog.

				\param fmt C-style format string.
				\param ... Variable arguments corresponding to the format string.
			*/
			void LogAlert(const char* fmt, ...);

			/*! Get the name registered for this Logger

				\return The logger name
			*/
			std::string GetName();

			/*! Get the session ID registered for this logger

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

			\return a list of registered logger names
		*/
		static std::vector<std::string> GetLoggerNames();
	};

	/*!
		@addtogroup coreapi
	 	@{
	*/
	std::string EscapeString(const std::string& s);
	std::string UnescapeString(const std::string& s);

	bool PreprocessSource(const std::string& source, const std::string& fileName, std::string& output,
	    std::string& errors, const std::vector<std::string>& includeDirs = std::vector<std::string>());

	void DisablePlugins();
	bool IsPluginsEnabled();
	bool InitPlugins(bool allowUserPlugins = true);
	/*!
		\deprecated Use `InitPlugins()`
	*/
	void InitCorePlugins();  // Deprecated, use InitPlugins
	/*!
		\deprecated Use `InitPlugins()`
	*/
	void InitUserPlugins();  // Deprecated, use InitPlugins
	void InitRepoPlugins();

	std::string GetBundledPluginDirectory();
	void SetBundledPluginDirectory(const std::string& path);
	std::string GetUserDirectory();

	std::string GetSettingsFileName();
	std::string GetRepositoriesDirectory();
	std::string GetInstallDirectory();
	std::string GetUserPluginDirectory();

	std::string GetPathRelativeToBundledPluginDirectory(const std::string& path);
	std::string GetPathRelativeToUserPluginDirectory(const std::string& path);
	std::string GetPathRelativeToUserDirectory(const std::string& path);

	bool ExecuteWorkerProcess(const std::string& path, const std::vector<std::string>& args, const DataBuffer& input,
	    std::string& output, std::string& errors, bool stdoutIsText = false, bool stderrIsText = true);

	std::string GetVersionString();
	std::string GetLicensedUserEmail();
	std::string GetProduct();
	std::string GetProductType();
	std::string GetSerialNumber();
	int GetLicenseCount();
	bool IsUIEnabled();
	uint32_t GetBuildId();

	bool AreAutoUpdatesEnabled();
	void SetAutoUpdatesEnabled(bool enabled);
	uint64_t GetTimeSinceLastUpdateCheck();
	void UpdatesChecked();

	std::string GetActiveUpdateChannel();
	void SetActiveUpdateChannel(const std::string& channel);

	void SetCurrentPluginLoadOrder(BNPluginLoadOrder order);
	void AddRequiredPluginDependency(const std::string& name);
	void AddOptionalPluginDependency(const std::string& name);
	/*!
		@}
	*/

	class BinaryView;

	/*! OpenView opens a file on disk and returns a BinaryView, attempting to use the most
	    relevant BinaryViewType and generating default load options (which are overridable).

	    If there is any error loading the file, nullptr will be returned and a log error will
	    be printed.

	    \warn You will need to call bv->GetFile()->Close() when you are finished using the
	    view returned by this function to free the resources it opened.

	    If no BinaryViewType is available to load the file, the `Mapped` view type will
	    attempt to load it, and will try to auto-detect the architecture. If no architecture
	    is detected or specified in the load options, the `Mapped` type will fail and this
	    function will also return nullptr.

	    \note Although general container file support is not complete, support for Universal
	    archives exists. It's possible to control the architecture preference with the
	    `files.universal.architecturePreference` setting. This setting is scoped to
	    SettingsUserScope and can be modified as follows:

	 	\code{.cpp}
		Json::Value options(Json::objectValue);
		options["files.universal.architecturePreference"] = Json::Value(Json::arrayValue);
		options["files.universal.architecturePreference"].append("arm64");
		Ref<BinaryView> bv = OpenView("/bin/ls", true, {}, options);
	 	\endcode

	    \param filename Path to filename or BNDB to open.
	    \param updateAnalysis If true, UpdateAnalysisAndWait() will be called after opening
	                          a BinaryView.
	    \param progress Optional function to be called with progress updates as the view is
	                    being loaded. If the function returns false, it will cancel OpenView.
	    \param options A Json object whose keys are setting identifiers and whose values are
	                   the desired settings.
	    \return Constructed view, or a nullptr Ref<BinaryView>
	*/
	Ref<BinaryView> OpenView(const std::string& filename, bool updateAnalysis = true, std::function<bool(size_t, size_t)> progress = {}, Json::Value options = Json::Value(Json::objectValue));

	/*! Open a BinaryView from a raw data buffer, initializing data views and loading settings.

	    \see BinaryNinja::OpenView(const std::string&, bool, std::function<bool(size_t, size_t)>, Json::Value)
	    for discussion of this function.

	    \param rawData Buffer with raw binary data to load (cannot load from bndb)
	    \param updateAnalysis If true, UpdateAnalysisAndWait() will be called after opening
	                          a BinaryView.
	    \param progress Optional function to be called with progress updates as the view is
	                    being loaded. If the function returns false, it will cancel OpenView.
	    \param options A Json object whose keys are setting identifiers and whose values are
	                   the desired settings.
	    \return Constructed view, or a nullptr Ref<BinaryView>
	*/
	Ref<BinaryView> OpenView(const DataBuffer& rawData, bool updateAnalysis = true, std::function<bool(size_t, size_t)> progress = {}, Json::Value options = Json::Value(Json::objectValue));


	/*! Open a BinaryView from a raw BinaryView, initializing data views and loading settings.

	    \see BinaryNinja::OpenView(const std::string&, bool, std::function<bool(size_t, size_t)>, Json::Value)
	    for discussion of this function.

	    \param rawData BinaryView with raw binary data to load
	    \param updateAnalysis If true, UpdateAnalysisAndWait() will be called after opening
	                          a BinaryView.
	    \param progress Optional function to be called with progress updates as the view is
	                    being loaded. If the function returns false, it will cancel OpenView.
	    \param options A Json object whose keys are setting identifiers and whose values are
	                   the desired settings.
	    \param isDatabase True if the view being loaded is the raw view of an already opened database.
	    \return Constructed view, or a nullptr Ref<BinaryView>
	*/
	Ref<BinaryView> OpenView(Ref<BinaryView> rawData, bool updateAnalysis = true, std::function<bool(size_t, size_t)> progress = {}, Json::Value options = Json::Value(Json::objectValue), bool isDatabase = false);

	/*! Demangles a Microsoft Visual Studio C++ name

	    \param[in] arch Architecture for the symbol. Required for pointer and integer sizes.
	    \param[in] mangledName a mangled Microsoft Visual Studio C++ name
	    \param[out] outType Pointer to Type to output
	    \param[out] outVarName QualifiedName reference to write the output name to.
	    \param[in] simplify Whether to simplify demangled names.

	    \ingroup demangle
	*/
	bool DemangleMS(Architecture* arch, const std::string& mangledName, Type** outType, QualifiedName& outVarName,
	    const bool simplify = false);

	/*! Demangles a Microsoft Visual Studio C++ name

	    This overload will use the view's "analysis.types.templateSimplifier" setting
	    	to determine whether to simplify the mangled name.

		\param[in] arch Architecture for the symbol. Required for pointer and integer sizes.
	    \param[in] mangledName a mangled Microsoft Visual Studio C++ name
	    \param[out] outType Pointer to Type to output
	    \param[out] outVarName QualifiedName reference to write the output name to.
	    \param[in] view View to check the analysis.types.templateSimplifier for

		\ingroup demangle
	*/
	bool DemangleMS(Architecture* arch, const std::string& mangledName, Type** outType, QualifiedName& outVarName,
	    const Ref<BinaryView>& view);

	/*! Demangles a GNU3 name

		\param[in] arch Architecture for the symbol. Required for pointer and integer sizes.
	    \param[in] mangledName a mangled GNU3 name
	    \param[out] outType Pointer to Type to output
	    \param[out] outVarName QualifiedName reference to write the output name to.
	    \param[in] simplify Whether to simplify demangled names.

	    \ingroup demangle
	*/
	bool DemangleGNU3(Ref<Architecture> arch, const std::string& mangledName, Type** outType, QualifiedName& outVarName,
	    const bool simplify = false);

	/*! Demangles a GNU3 name

	    This overload will use the view's "analysis.types.templateSimplifier" setting
	        to determine whether to simplify the mangled name.

		\param[in] arch Architecture for the symbol. Required for pointer and integer sizes.
	    \param[in] mangledName a mangled GNU3 name
	    \param[out] outType Pointer to Type to output
	    \param[out] outVarName QualifiedName reference to write the output name to.
	    \param[in] view View to check the analysis.types.templateSimplifier for

	    \ingroup demangle
	*/
	bool DemangleGNU3(Ref<Architecture> arch, const std::string& mangledName, Type** outType, QualifiedName& outVarName,
	    const Ref<BinaryView>& view);

	/*!
		\ingroup mainthread
	*/
	void RegisterMainThread(MainThreadActionHandler* handler);

	/*!
		\ingroup mainthread
	*/
	Ref<MainThreadAction> ExecuteOnMainThread(const std::function<void()>& action);

	/*!
		\ingroup mainthread
	*/
	void ExecuteOnMainThreadAndWait(const std::function<void()>& action);

	/*!
		\ingroup mainthread
	*/
	bool IsMainThread();

	/*!
		\ingroup mainthread
	*/
	void WorkerEnqueue(const std::function<void()>& action);

	/*!
		\ingroup mainthread
	*/
	void WorkerEnqueue(RefCountObject* owner, const std::function<void()>& action);

	/*!
		\ingroup mainthread
	*/
	void WorkerPriorityEnqueue(const std::function<void()>& action);

	/*!
		\ingroup mainthread
	*/
	void WorkerPriorityEnqueue(RefCountObject* owner, const std::function<void()>& action);

	/*!
		\ingroup mainthread
	*/
	void WorkerInteractiveEnqueue(const std::function<void()>& action);

	/*!
		\ingroup mainthread
	*/
	void WorkerInteractiveEnqueue(RefCountObject* owner, const std::function<void()>& action);

	/*!
		\ingroup mainthread
	*/
	size_t GetWorkerThreadCount();

	/*!
		\ingroup mainthread
	*/
	void SetWorkerThreadCount(size_t count);

	std::string MarkdownToHTML(const std::string& contents);

	void RegisterInteractionHandler(InteractionHandler* handler);

	/*! Displays contents to the user in the UI or on the command-line

		\note This API functions differently on the command-line vs the UI. In the UI, it will be rendered in a new tab. From
		the command line, a simple text prompt is used.

	 	\ingroup interaction

		\param title Title for the report
		\param contents Contents of the report
	*/
	void ShowPlainTextReport(const std::string& title, const std::string& contents);

	/*! Displays markdown contents to the user in the UI or on the command-line

	 	\note This API functions differently on the command-line vs the UI. In the UI, it will be rendered in a new tab. From
		the command line, a simple text prompt is used.

	 	\ingroup interaction

		\param title Title for the report
		\param contents Markdown contents of the report
		\param plainText Plaintext contents of the report (used on the command line)
	*/
	void ShowMarkdownReport(const std::string& title, const std::string& contents, const std::string& plainText = "");

	/*! Displays HTML contents to the user in the UI or on the command-line

		\note This API functions differently on the command-line vs the UI. In the UI, it will be rendered in a new tab. From
		the command line, a simple text prompt is used.
		\note This API doesn't support clickable references into an existing BinaryView.

	 	\ingroup interaction

		\param title Title for the report
		\param contents HTML contents of the report
		\param plainText Plaintext contents of the report (used on the command line)
	*/
	void ShowHTMLReport(const std::string& title, const std::string& contents, const std::string& plainText = "");

	/*! Displays a flow graph in UI applications and nothing in command-line applications.

	 	\note This API doesn't support clickable references into an existing BinaryView.
	 	\note This API has no effect outside of the UI

	 	\ingroup interaction

		\param title Title for the report
		\param graph FlowGraph object to be rendered.
	*/
	void ShowGraphReport(const std::string& title, FlowGraph* graph);

	/*! Show a collection of reports

	 	\ingroup interaction

		\param title Title for the collection of reports
		\param reports Collection of reports to show
	*/
	void ShowReportCollection(const std::string& title, ReportCollection* reports);

	/*! Prompts the user to input a string with the given prompt and title

	 	\ingroup interaction

		\param[out] result Reference to the string the result will be copied to
		\param[in] prompt Prompt for the input
		\param[in] title Title for the input popup when used in UI
		\return Whether a line was successfully received
	*/
	bool GetTextLineInput(std::string& result, const std::string& prompt, const std::string& title);

	/*! Prompts the user to input an integer with the given prompt and title

	 	\ingroup interaction
		\param[out] result Reference to the int64_t the result will be copied to
		\param[in] prompt Prompt for the input
		\param[in] title Title for the input popup when used in UI
		\return Whether an integer was successfully received
	*/
	bool GetIntegerInput(int64_t& result, const std::string& prompt, const std::string& title);

	/*! Prompts the user to input an unsigned integer with the given prompt and title

	 	\ingroup interaction
		\param[out] result Reference to the uint64_t the result will be copied to
		\param[in] prompt Prompt for the input
		\param[in] title Title for the input popup when used in UI
		\return Whether an integer was successfully received
	*/
	bool GetAddressInput(uint64_t& result, const std::string& prompt, const std::string& title);

	/*! Prompts the user to select the one of the provided choices

	 	\ingroup interaction
		\param[out] idx Reference to the size_t the resulting index selected will be copied to
		\param[in] prompt Prompt for the input
		\param[in] title Title for the input popup when used in UI
		\param[in] choices List of string choices for the user to select from
		\return Whether a choice was successfully picked
	*/
	bool GetChoiceInput(
	    size_t& idx, const std::string& prompt, const std::string& title, const std::vector<std::string>& choices);

	/*! Prompts the user for a file name to open

		Multiple file selection groups can be included if separated by two semicolons. Multiple file wildcards may be
	 	specified by using a space within the parenthesis.

		Also, a simple selector of "\*.extension" by itself may also be used instead of specifying the description.

	 	\ingroup interaction

		\param[out] result Reference to the string the result will be copied to
		\param[in] prompt Prompt for the dialog
		\param[in] ext Optional, file extension
		\return Whether a filename was successfully received
	*/
	bool GetOpenFileNameInput(std::string& result, const std::string& prompt, const std::string& ext = "");

	/*! Prompts the user for a file name to save as, optionally providing a file extension and defaultName

	 	\ingroup interaction

		\param[out] result Reference to the string the result will be copied to
		\param[in] prompt Prompt for the dialog
		\param[in] ext Optional, file extension
		\param[in] defaultName Optional, default filename
		\return Whether a filename was successfully received
	*/
	bool GetSaveFileNameInput(std::string& result, const std::string& prompt, const std::string& ext = "",
	    const std::string& defaultName = "");

	/*! Prompts the user for a directory name to save as, optionally providing a default_name

	 	\ingroup interaction
		\param[out] result Reference to the string the result will be copied to
		\param[in] prompt Prompt for the dialog
		\param[in] defaultName Optional, default directory name
		\return Whether a directory was successfully received
	*/
	bool GetDirectoryNameInput(std::string& result, const std::string& prompt, const std::string& defaultName = "");

	/*! Prompts the user for a set of inputs specified in `fields` with given title.
		The fields parameter is a list containing FieldInputFields

	 	\ingroup interaction
		\param[in,out] fields reference to a list containing FieldInputFields
		\param[in] title Title of the Form
		\return Whether the form was successfully filled out
	*/
	bool GetFormInput(std::vector<FormInputField>& fields, const std::string& title);

	/*! Displays a configurable message box in the UI, or prompts on the console as appropriate

		\param title Title for the message box
		\param text Contents of the message box
		\param buttons
	 	\parblock
	    Button Set type to display to the user

	    	OKButtonSet - Displays only an OK button
	    	YesNoButtonSet - Displays a Yes and a No button
	    	YesNoCancelButtonSet - Displays a Yes, No, and Cancel button
	    \endparblock
		\param icon Icons to display to the user

	 	\ingroup interaction

		\return Which button was selected'
	 	\retval NoButton No was clicked, or the box was closed and had type YesNoButtonSet
	 	\retval YesButton Yes was clicked
	 	\retval OKButton Ok Button was clicked, or the box was closed and had type OKButtonSet
	 	\retval CancelButton Cancel button was clicked or the dialog box was closed and had type YesNoCancelButtonSet
	*/
	BNMessageBoxButtonResult ShowMessageBox(const std::string& title, const std::string& text,
	    BNMessageBoxButtonSet buttons = OKButtonSet, BNMessageBoxIcon icon = InformationIcon);

	/*! Opens a given url in the user's web browser, if available.

	 	\ingroup interaction

		\param url URL to open
		\return Whether a URL was successfully opened.
	*/
	bool OpenUrl(const std::string& url);

	/*! Run a given task in a background thread, and show an updating progress bar which the user can cancel

		\param title Dialog title
		\param canCancel If the task can be cancelled
		\param task Function to perform the task, taking as a parameter a function which should be called to report progress
		            updates and check for cancellation. If the progress function returns false, the user has requested
		            to cancel, and the task should handle this appropriately.
		\return True if not cancelled
	*/
	bool RunProgressDialog(const std::string& title, bool canCancel, std::function<void(std::function<bool(size_t, size_t)> progress)> task);

	/*!
	    Split a single progress function into equally sized subparts.
	    This function takes the original progress function and returns a new function whose signature
	    is the same but whose output is shortened to correspond to the specified subparts.

	    E.g. If subpart = 0 and subpartCount = 3, this returns a function that calls originalFn and has
	    all of its progress multiplied by 1/3 and 0/3 added.

	    Internally this works by calling originalFn with total = 1000000 and doing math on the current value

	    \param originalFn Original progress function (usually updates a UI)
	    \param subpart Index of subpart whose function to return, from 0 to (subpartCount - 1)
	    \param subpartCount Total number of subparts
	    \return A function that will call originalFn() within a modified progress region
	*/
	std::function<bool(size_t, size_t)> SplitProgress(
	    std::function<bool(size_t, size_t)> originalFn, size_t subpart, size_t subpartCount);


	/*!
	    Split a single progress function into subparts.
	    This function takes the original progress function and returns a new function whose signature
	    is the same but whose output is shortened to correspond to the specified subparts.

	    The length of a subpart is proportional to the sum of all the weights.
	    E.g. If subpart = 1 and subpartWeights = { 0.25, 0.5, 0.25 }, this will return a function that calls
	    originalFn and maps its progress to the range [0.25, 0.75]

	    Internally this works by calling originalFn with total = 1000000 and doing math on the current value

	    \param originalFn Original progress function (usually updates a UI)
	    \param subpart Index of subpart whose function to return, from 0 to (subpartWeights.size() - 1)
	    \param subpartWeights Weights of subparts, described above
	    \return A function that will call originalFn() within a modified progress region
	*/
	std::function<bool(size_t, size_t)> SplitProgress(
	    std::function<bool(size_t, size_t)> originalFn, size_t subpart, std::vector<double> subpartWeights);

	struct ProgressContext
	{
		std::function<bool(size_t, size_t)> callback;
	};

	bool ProgressCallback(void* ctxt, size_t current, size_t total);

	std::string GetUniqueIdentifierString();

	std::map<std::string, uint64_t> GetMemoryUsageInfo();

	/*!
		\ingroup databuffer
	*/
	class DataBuffer
	{
		BNDataBuffer* m_buffer;

	  public:
		DataBuffer();
		DataBuffer(size_t len);
		DataBuffer(const void* data, size_t len);
		DataBuffer(const DataBuffer& buf);
		DataBuffer(DataBuffer&& buf);
		DataBuffer(BNDataBuffer* buf);
		~DataBuffer();

		DataBuffer& operator=(const DataBuffer& buf);
		DataBuffer& operator=(DataBuffer&& buf);

		BNDataBuffer* GetBufferObject() const { return m_buffer; }

		void* GetData();
		const void* GetData() const;
		void* GetDataAt(size_t offset);
		const void* GetDataAt(size_t offset) const;
		size_t GetLength() const;

		void SetSize(size_t len);
		void Clear();
		void Append(const void* data, size_t len);
		void Append(const DataBuffer& buf);
		void AppendByte(uint8_t val);

		DataBuffer GetSlice(size_t start, size_t len);

		uint8_t& operator[](size_t offset);
		const uint8_t& operator[](size_t offset) const;

		bool operator==(const DataBuffer& other) const;
		bool operator!=(const DataBuffer& other) const;

		std::string ToEscapedString() const;
		static DataBuffer FromEscapedString(const std::string& src);
		std::string ToBase64() const;
		static DataBuffer FromBase64(const std::string& src);

		bool ZlibCompress(DataBuffer& output) const;
		bool ZlibDecompress(DataBuffer& output) const;
	};

	/*! TemporaryFile is used for creating temporary files, stored (temporarily) in the system's default temporary file
	 		directory.

	 	\ingroup tempfile
	*/
	class TemporaryFile : public CoreRefCountObject<BNTemporaryFile, BNNewTemporaryFileReference, BNFreeTemporaryFile>
	{
	  public:
		TemporaryFile();

		/*! Create a new temporary file with BinaryNinja::DataBuffer contents.

	    	\param contents DataBuffer with contents to write to the file.
		*/
		TemporaryFile(const DataBuffer& contents);

		/*! Create a new temporary file with string contents.

	        \param contents std::string with contents to write to the file.
		*/
		TemporaryFile(const std::string& contents);
		TemporaryFile(BNTemporaryFile* file);

		bool IsValid() const { return m_object != nullptr; }

		/*! Path to the TemporaryFile on the filesystem.
		*/
		std::string GetPath() const;

		/*! DataBuffer with contents of the file.
		*/
		DataBuffer GetContents();
	};

	/*!
		\ingroup filemetadata
	*/
	class NavigationHandler
	{
	  private:
		BNNavigationHandler m_callbacks;

		static char* GetCurrentViewCallback(void* ctxt);
		static uint64_t GetCurrentOffsetCallback(void* ctxt);
		static bool NavigateCallback(void* ctxt, const char* view, uint64_t offset);

	  public:
		NavigationHandler();
		virtual ~NavigationHandler() {}

		BNNavigationHandler* GetCallbacks() { return &m_callbacks; }

		virtual std::string GetCurrentView() = 0;
		virtual uint64_t GetCurrentOffset() = 0;
		virtual bool Navigate(const std::string& view, uint64_t offset) = 0;
	};

	/*!

		\ingroup coreapi
	*/
	class User : public CoreRefCountObject<BNUser, BNNewUserReference, BNFreeUser>
	{
	  private:
		std::string m_id;
		std::string m_name;
		std::string m_email;

	  public:
		User(BNUser* user);
		std::string GetName();
		std::string GetEmail();
		std::string GetId();
	};

	/*! `InstructionTextToken` is used to tell the core about the various components in the disassembly views.

		The below table is provided for documentation purposes but the complete list of TokenTypes is available at
		`InstructionTextTokenType`. Note that types marked as `Not emitted by architectures` are not intended to be used
		by Architectures during lifting. Rather, they are added by the core during analysis or display. UI plugins,
		however, may make use of them as appropriate.

		Uses of tokens include plugins that parse the output of an architecture (though parsing IL is recommended),
	 	or additionally, applying color schemes appropriately.

			========================== ============================================
			InstructionTextTokenType   Description
			========================== ============================================
			AddressDisplayToken        **Not emitted by architectures**
			AnnotationToken            **Not emitted by architectures**
			ArgumentNameToken          **Not emitted by architectures**
			BeginMemoryOperandToken    The start of memory operand
			CharacterConstantToken     A printable character
			CodeRelativeAddressToken   **Not emitted by architectures**
			CodeSymbolToken            **Not emitted by architectures**
			DataSymbolToken            **Not emitted by architectures**
			EndMemoryOperandToken      The end of a memory operand
			ExternalSymbolToken        **Not emitted by architectures**
			FieldNameToken             **Not emitted by architectures**
			FloatingPointToken         Floating point number
			HexDumpByteValueToken      **Not emitted by architectures**
			HexDumpInvalidByteToken    **Not emitted by architectures**
			HexDumpSkippedByteToken    **Not emitted by architectures**
			HexDumpTextToken           **Not emitted by architectures**
			ImportToken                **Not emitted by architectures**
			IndirectImportToken        **Not emitted by architectures**
			InstructionToken           The instruction mnemonic
			IntegerToken               Integers
			KeywordToken               **Not emitted by architectures**
			LocalVariableToken         **Not emitted by architectures**
			NameSpaceSeparatorToken    **Not emitted by architectures**
			NameSpaceToken             **Not emitted by architectures**
			OpcodeToken                **Not emitted by architectures**
			OperandSeparatorToken      The comma or delimiter that separates tokens
			PossibleAddressToken       Integers that are likely addresses
			RegisterToken              Registers
			StringToken                **Not emitted by architectures**
			StructOffsetToken          **Not emitted by architectures**
			TagToken                   **Not emitted by architectures**
			TextToken                  Used for anything not of another type.
			CommentToken               Comments
			TypeNameToken              **Not emitted by architectures**
			========================== ============================================
	*/
	struct InstructionTextToken
	{
		enum
		{
			WidthIsByteCount = 0
		};

		BNInstructionTextTokenType type;
		std::string text;
		uint64_t value;
		uint64_t width;
		size_t size, operand;
		BNInstructionTextTokenContext context;
		uint8_t confidence;
		uint64_t address;
		std::vector<std::string> typeNames;

		InstructionTextToken();
		InstructionTextToken(uint8_t confidence, BNInstructionTextTokenType t, const std::string& txt);
		InstructionTextToken(BNInstructionTextTokenType type, const std::string& text, uint64_t value = 0,
		    size_t size = 0, size_t operand = BN_INVALID_OPERAND, uint8_t confidence = BN_FULL_CONFIDENCE,
		    const std::vector<std::string>& typeName = {}, uint64_t width = WidthIsByteCount);
		InstructionTextToken(BNInstructionTextTokenType type, BNInstructionTextTokenContext context,
		    const std::string& text, uint64_t address, uint64_t value = 0, size_t size = 0,
		    size_t operand = BN_INVALID_OPERAND, uint8_t confidence = BN_FULL_CONFIDENCE,
		    const std::vector<std::string>& typeName = {}, uint64_t width = WidthIsByteCount);
		InstructionTextToken(const BNInstructionTextToken& token);

		InstructionTextToken WithConfidence(uint8_t conf);
		static BNInstructionTextToken* CreateInstructionTextTokenList(const std::vector<InstructionTextToken>& tokens);
		static void FreeInstructionTextTokenList(
		    BNInstructionTextToken* tokens, size_t count);
		static std::vector<InstructionTextToken> ConvertAndFreeInstructionTextTokenList(
		    BNInstructionTextToken* tokens, size_t count);
		static std::vector<InstructionTextToken> ConvertInstructionTextTokenList(
		    const BNInstructionTextToken* tokens, size_t count);
	};

	struct UndoEntry;

	/*!

		\ingroup database
	*/
	struct DatabaseException : std::runtime_error
	{
		DatabaseException(const std::string& desc) : std::runtime_error(desc.c_str()) {}
	};

	/*! Maintains access to the raw data stored in Snapshots and various
    	other Database-related structures.

		\ingroup database
	*/
	class KeyValueStore : public CoreRefCountObject<BNKeyValueStore, BNNewKeyValueStoreReference, BNFreeKeyValueStore>
	{
	  public:
		KeyValueStore();
		KeyValueStore(const DataBuffer& buffer);
		KeyValueStore(BNKeyValueStore* store);

		std::vector<std::string> GetKeys() const;

		bool HasValue(const std::string& name) const;
		Json::Value GetValue(const std::string& name) const;
		DataBuffer GetBuffer(const std::string& name) const;
		void SetValue(const std::string& name, const Json::Value& value);
		void SetBuffer(const std::string& name, const DataBuffer& value);

		DataBuffer GetSerializedData() const;

		void BeginNamespace(const std::string& name);
		void EndNamespace();

		bool IsEmpty() const;
		size_t ValueSize() const;
		size_t DataSize() const;
		size_t ValueStorageSize() const;
		size_t NamespaceSize() const;
	};

	class Database;

	/*! A model of an individual database snapshot, created on save.

		\ingroup database
	*/
	class Snapshot : public CoreRefCountObject<BNSnapshot, BNNewSnapshotReference, BNFreeSnapshot>
	{
	  public:
		Snapshot(BNSnapshot* snapshot);

		Ref<Database> GetDatabase();
		int64_t GetId();
		std::string GetName();
		bool IsAutoSave();
		bool HasContents();
		bool HasData();
		bool HasUndo();
		Ref<Snapshot> GetFirstParent();
		std::vector<Ref<Snapshot>> GetParents();
		std::vector<Ref<Snapshot>> GetChildren();
		DataBuffer GetFileContents();
		DataBuffer GetFileContentsHash();
		std::vector<UndoEntry> GetUndoEntries();
		std::vector<UndoEntry> GetUndoEntries(const std::function<bool(size_t, size_t)>& progress);
		Ref<KeyValueStore> ReadData();
		Ref<KeyValueStore> ReadData(const std::function<bool(size_t, size_t)>& progress);
		bool HasAncestor(Ref<Snapshot> other);
	};

	class FileMetadata;

	/*! Provides lower level access to raw snapshot data used to construct analysis data

		\ingroup database
	*/
	class Database : public CoreRefCountObject<BNDatabase, BNNewDatabaseReference, BNFreeDatabase>
	{
	  public:
		Database(BNDatabase* database);

		bool SnapshotHasData(int64_t id);
		Ref<Snapshot> GetSnapshot(int64_t id);
		std::vector<Ref<Snapshot>> GetSnapshots();
		void SetCurrentSnapshot(int64_t id);
		Ref<Snapshot> GetCurrentSnapshot();
		int64_t WriteSnapshotData(std::vector<int64_t> parents, Ref<BinaryView> file, const std::string& name,
		    const Ref<KeyValueStore>& data, bool autoSave, const std::function<bool(size_t, size_t)>& progress);
		bool StoreDataForSnapshot(int64_t id, const Ref<KeyValueStore>& data, const std::function<bool(size_t, size_t)>& progress);
		void TrimSnapshot(int64_t id);
		void RemoveSnapshot(int64_t id);

		std::vector<std::string> GetGlobalKeys() const;
		bool HasGlobal(const std::string& key) const;
		Json::Value ReadGlobal(const std::string& key) const;
		void WriteGlobal(const std::string& key, const Json::Value& val);
		DataBuffer ReadGlobalData(const std::string& key) const;
		void WriteGlobalData(const std::string& key, const DataBuffer& val);

		Ref<FileMetadata> GetFile();

		Ref<KeyValueStore> ReadAnalysisCache() const;
		void WriteAnalysisCache(Ref<KeyValueStore> val);
	};

	/*!

		\ingroup undo
	*/
	struct UndoAction
	{
		BNActionType actionType;
		std::string summaryText;
		std::vector<InstructionTextToken> summaryTokens;

		UndoAction() {};
		UndoAction(const BNUndoAction& action);
	};

	/*!

		\ingroup undo
	*/
	struct UndoEntry
	{
		Ref<User> user;
		std::string hash;
		std::vector<UndoAction> actions;
		uint64_t timestamp;
	};

	/*!

		\ingroup coreapi
	*/
	struct MergeResult
	{
		BNMergeStatus status;
		UndoAction action;
		std::string hash;

		MergeResult() : status(NOT_APPLICABLE) {}
		MergeResult(const BNMergeResult& result);
	};

	/*!
		\ingroup filemetadata
	*/
	class SaveSettings : public CoreRefCountObject<BNSaveSettings, BNNewSaveSettingsReference, BNFreeSaveSettings>
	{
	  public:
		SaveSettings();
		SaveSettings(BNSaveSettings* settings);

		bool IsOptionSet(BNSaveOption option) const;
		void SetOption(BNSaveOption option, bool state = true);
	};

	/*!
		\ingroup filemetadata
	*/
	class FileMetadata : public CoreRefCountObject<BNFileMetadata, BNNewFileReference, BNFreeFileMetadata>
	{
	  public:
		FileMetadata();
		FileMetadata(const std::string& filename);
		FileMetadata(BNFileMetadata* file);

		/*! Close the underlying file handle
		*/
		void Close();

		void SetNavigationHandler(NavigationHandler* handler);

		/*! Get the original name of the binary opened if a bndb, otherwise the current filename

			\return The original name of the binary opened if a bndb, otherwise returns the current filename
		*/
		std::string GetOriginalFilename() const;

		/*! If the filename is not open in a BNDB, sets the filename for the current file.

			\param name New name
		*/
		void SetOriginalFilename(const std::string& name);

		/*!
			\return The name of the open bndb or binary filename
		*/
		std::string GetFilename() const;

		/*! Set the filename for the current BNDB or binary.

		 	\param name Set the filename for the current BNDB or binary.
		*/
		void SetFilename(const std::string& name);

		/*! Whether the file has unsaved modifications

			\return Whether the file has unsaved modifications
		*/
		bool IsModified() const;

		/*! Whether auto-analysis results have changed.

			\return Whether auto-analysis results have changed.
		*/
		bool IsAnalysisChanged() const;

		/*! Mark file as having unsaved changes
		*/
		void MarkFileModified();

		/*! Mark file as having been saved (inverse of MarkFileModified)
		*/
		void MarkFileSaved();

		bool IsSnapshotDataAppliedWithoutError() const;

		/*! Whether the FileMetadata is backed by a database, or if specified,
		    	a specific BinaryView type

			\param binaryViewType Type for the BinaryView
		 	\return Whether the FileMetadata is backed by a database
		*/
		bool IsBackedByDatabase(const std::string& binaryViewType = "") const;

		/*! Writes the current database (.bndb) out to the specified file.

		 	\param name path and filename to write the bndb to. Should have ".bndb" appended to it.
		 	\param data BinaryView to save the database from
		 	\param settings Special save options
		 	\return Whether the save was successful
		*/
		bool CreateDatabase(const std::string& name, BinaryView* data, Ref<SaveSettings> settings);

		/*! Writes the current database (.bndb) out to the specified file.

		    \param name path and filename to write the bndb to. Should have ".bndb" appended to it.
		    \param data BinaryView to save the database from
		    \param progressCallback callback function to send save progress to.
		    \param settings Special save options
		    \return Whether the save was successful
		*/
		bool CreateDatabase(const std::string& name, BinaryView* data,
		    const std::function<bool(size_t progress, size_t total)>& progressCallback, Ref<SaveSettings> settings);

		/*! Open an existing database from a given path

		 	\param path Path to the existing database
		 	\return The resulting BinaryView, if the load was successful
		*/
		Ref<BinaryView> OpenExistingDatabase(const std::string& path);

		/*! Open an existing database from a given path with a progress callback

		    \param path Path to the existing database
			\param progressCallback callback function to send load progress to.
		    \return The resulting BinaryView, if the load was successful
		*/
		Ref<BinaryView> OpenExistingDatabase(
		    const std::string& path, const std::function<bool(size_t progress, size_t total)>& progressCallback);
		Ref<BinaryView> OpenDatabaseForConfiguration(const std::string& path);

		/*! Save the current database to the already created file.

		 	Note: CreateDatabase should have been called prior to calling this.

			\param data BinaryView to save the data of
		    \param settings Special save options
		    \return Whether the save was successful
		*/
		bool SaveAutoSnapshot(BinaryView* data, Ref<SaveSettings> settings);

		/*! Save the current database to the already created file.

		    Note: CreateDatabase should have been called prior to calling this.

		    \param data BinaryView to save the data of
		    \param settings Special save options
		    \param progressCallback callback function to send save progress to
		    \return Whether the save was successful
		*/
		bool SaveAutoSnapshot(BinaryView* data,
		    const std::function<bool(size_t progress, size_t total)>& progressCallback, Ref<SaveSettings> settings);
		void GetSnapshotData(
		    Ref<KeyValueStore> data, Ref<KeyValueStore> cache, const std::function<bool(size_t, size_t)>& progress);
		void ApplySnapshotData(BinaryView* file, Ref<KeyValueStore> data, Ref<KeyValueStore> cache,
		    const std::function<bool(size_t, size_t)>& progress, bool openForConfiguration = false,
		    bool restoreRawView = true);
		Ref<Database> GetDatabase();

		/*! Rebase the given BinaryView to a new address

			\param data BinaryView to rebase
		    \param address Address to rebase to
		    \return Whether the rebase was successful
		*/
		bool Rebase(BinaryView* data, uint64_t address);

		/*! Rebase the given BinaryView to a new address

			\param data BinaryView to rebase
		    \param address Address to rebase to
		    \param progressCallback Callback function to pass rebase progress to
		    \return Whether the rebase was successful
		*/
		bool Rebase(BinaryView* data, uint64_t address,
		    const std::function<bool(size_t progress, size_t total)>& progressCallback);
		bool CreateSnapshotedView(BinaryView* data, const std::string& viewName);
		bool CreateSnapshotedView(BinaryView* data, const std::string& viewName,
								  const std::function<bool(size_t progress, size_t total)>& progressCallback);

		MergeResult MergeUserAnalysis(const std::string& name, const std::function<bool(size_t, size_t)>& progress,
		    const std::vector<std::string> excludedHashes = {});

		/*! Start recording actions taken so they can be undone at some point
		*/
		void BeginUndoActions();

		/*!  Commit the actions taken since the last commit to the undo database.
		*/
		void CommitUndoActions();

		/*! \return Whether it is possible to perform an Undo
		*/
		bool CanUndo();

		/*! Undo the last committed action in the undo database.
		*/
		bool Undo();

		/*! \return Whether it is possible to perform a Redo
		*/
		bool CanRedo();

		/*! Redo the last committed action in the undo database.
		*/
		bool Redo();

		std::vector<Ref<User>> GetUsers();
		std::vector<UndoEntry> GetUndoEntries();
		std::vector<UndoEntry> GetRedoEntries();
		std::optional<UndoEntry> GetLastUndoEntry();
		std::optional<UndoEntry> GetLastRedoEntry();
		std::optional<std::string> GetLastUndoEntryTitle();
		std::optional<std::string> GetLastRedoEntryTitle();
		void ClearUndoEntries();

		bool OpenProject();
		void CloseProject();
		bool IsProjectOpen();

		/*! Get the current View name, e.g. ``Linear:ELF``, ``Graph:PE``

		    \return The current view name
		*/
		std::string GetCurrentView();

		/*! Get the current offset in the current view

		    \return The current offset
		*/
		uint64_t GetCurrentOffset();

		/*! Navigate to the specified virtual address in the specified view

		 	\param view View name. e.g. ``Linear:ELF``, ``Graph:PE``
		 	\param offset Virtual address to navigate to
		 	\return Whether the navigation was successful.
		*/
		bool Navigate(const std::string& view, uint64_t offset);

		/*! Get the BinaryView for a specific View type

		    \param name View name. e.g. ``Linear:ELF``, ``Graph:PE``
		    \return The BinaryView, if it exists
		*/
		BinaryNinja::Ref<BinaryNinja::BinaryView> GetViewOfType(const std::string& name);

		/*! List of View names that exist within the current file

		    \return List of View Names
		*/
		std::vector<std::string> GetExistingViews() const;

		/*! Get the current Session ID for this file.

		 	\see This is used in Logger and LogRegistry to determine what tab logs are sent to.

		    \return Current Session ID
		*/
		size_t GetSessionId() const;

		/*! Explicitly unregister a binary view of the given type from this file.

		    \note There is no need to unregister a binary view in ordinary situations. Binary views will be
		    automatically unregistered from the file when the file itself is about to be freed. Also, when a
		    binary view with the same type is created, the old one is automatically unregistered from the file.

		    Only use this function when you wish to explicitly remove the binary view from the file. For example,
		    in the debugger, this method is used to remove the Debugger view from the file after the target exits.

		    This also does not necessarily free the binary, because there could be other references to it.

		    \param type the type of the view to unregister
		    \param data the binary view to unregister
		*/
		void UnregisterViewOfType(const std::string& type, BinaryNinja::Ref<BinaryNinja::BinaryView> data);
	};

	class Function;
	struct DataVariable;
	class Symbol;
	class Tag;
	class TagType;
	struct TagReference;
	class Section;
	class Segment;
	class Component;

	/*!

		\ingroup binaryview
	*/
	class BinaryDataNotification
	{
	  private:
		BNBinaryDataNotification m_callbacks;

		static void DataWrittenCallback(void* ctxt, BNBinaryView* data, uint64_t offset, size_t len);
		static void DataInsertedCallback(void* ctxt, BNBinaryView* data, uint64_t offset, size_t len);
		static void DataRemovedCallback(void* ctxt, BNBinaryView* data, uint64_t offset, uint64_t len);
		static void FunctionAddedCallback(void* ctxt, BNBinaryView* data, BNFunction* func);
		static void FunctionRemovedCallback(void* ctxt, BNBinaryView* data, BNFunction* func);
		static void FunctionUpdatedCallback(void* ctxt, BNBinaryView* data, BNFunction* func);
		static void FunctionUpdateRequestedCallback(void* ctxt, BNBinaryView* data, BNFunction* func);
		static void DataVariableAddedCallback(void* ctxt, BNBinaryView* data, BNDataVariable* var);
		static void DataVariableRemovedCallback(void* ctxt, BNBinaryView* data, BNDataVariable* var);
		static void DataVariableUpdatedCallback(void* ctxt, BNBinaryView* data, BNDataVariable* var);
		static void SymbolAddedCallback(void* ctxt, BNBinaryView* view, BNSymbol* sym);
		static void SymbolUpdatedCallback(void* ctxt, BNBinaryView* view, BNSymbol* sym);
		static void SymbolRemovedCallback(void* ctxt, BNBinaryView* view, BNSymbol* sym);
		static void DataMetadataUpdatedCallback(void* ctxt, BNBinaryView* object, uint64_t offset);
		static void TagTypeUpdatedCallback(void* ctxt, BNBinaryView* object, BNTagType* tagType);
		static void TagAddedCallback(void* ctxt, BNBinaryView* object, BNTagReference* tagRef);
		static void TagUpdatedCallback(void* ctxt, BNBinaryView* object, BNTagReference* tagRef);
		static void TagRemovedCallback(void* ctxt, BNBinaryView* object, BNTagReference* tagRef);
		static void StringFoundCallback(void* ctxt, BNBinaryView* data, BNStringType type, uint64_t offset, size_t len);
		static void StringRemovedCallback(
		    void* ctxt, BNBinaryView* data, BNStringType type, uint64_t offset, size_t len);
		static void TypeDefinedCallback(void* ctxt, BNBinaryView* data, BNQualifiedName* name, BNType* type);
		static void TypeUndefinedCallback(void* ctxt, BNBinaryView* data, BNQualifiedName* name, BNType* type);
		static void TypeReferenceChangedCallback(void* ctx, BNBinaryView* data, BNQualifiedName* name, BNType* type);
		static void TypeFieldReferenceChangedCallback(
		    void* ctx, BNBinaryView* data, BNQualifiedName* name, uint64_t offset);
		static void SegmentAddedCallback(void* ctx, BNBinaryView* data, BNSegment* segment);
		static void SegmentUpdatedCallback(void* ctx, BNBinaryView* data, BNSegment* segment);
		static void SegmentRemovedCallback(void* ctx, BNBinaryView* data, BNSegment* segment);
		static void SectionAddedCallback(void* ctx, BNBinaryView* data, BNSection* section);
		static void SectionUpdatedCallback(void* ctx, BNBinaryView* data, BNSection* section);
		static void SectionRemovedCallback(void* ctx, BNBinaryView* data, BNSection* section);
		static void ComponentNameUpdatedCallback(void* ctxt, BNBinaryView* data, char* previousName, BNComponent* component);
		static void ComponentAddedCallback(void* ctxt, BNBinaryView* data, BNComponent* component);
		static void ComponentRemovedCallback(
			void* ctxt, BNBinaryView* data, BNComponent* formerParent, BNComponent* component);
		static void ComponentMovedCallback(
			void* ctxt, BNBinaryView* data, BNComponent* formerParent, BNComponent* newParent, BNComponent* component);
		static void ComponentFunctionAddedCallback(void* ctxt, BNBinaryView* data, BNComponent* component, BNFunction* function);
		static void ComponentFunctionRemovedCallback(void* ctxt, BNBinaryView* data, BNComponent* component, BNFunction* function);


	  public:
		BinaryDataNotification();
		virtual ~BinaryDataNotification() {}

		BNBinaryDataNotification* GetCallbacks() { return &m_callbacks; }

		virtual void OnBinaryDataWritten(BinaryView* view, uint64_t offset, size_t len)
		{
			(void)view;
			(void)offset;
			(void)len;
		}
		virtual void OnBinaryDataInserted(BinaryView* view, uint64_t offset, size_t len)
		{
			(void)view;
			(void)offset;
			(void)len;
		}
		virtual void OnBinaryDataRemoved(BinaryView* view, uint64_t offset, uint64_t len)
		{
			(void)view;
			(void)offset;
			(void)len;
		}
		virtual void OnAnalysisFunctionAdded(BinaryView* view, Function* func)
		{
			(void)view;
			(void)func;
		}
		virtual void OnAnalysisFunctionRemoved(BinaryView* view, Function* func)
		{
			(void)view;
			(void)func;
		}
		virtual void OnAnalysisFunctionUpdated(BinaryView* view, Function* func)
		{
			(void)view;
			(void)func;
		}
		virtual void OnAnalysisFunctionUpdateRequested(BinaryView* view, Function* func)
		{
			(void)view;
			(void)func;
		}
		virtual void OnDataVariableAdded(BinaryView* view, const DataVariable& var)
		{
			(void)view;
			(void)var;
		}
		virtual void OnDataVariableRemoved(BinaryView* view, const DataVariable& var)
		{
			(void)view;
			(void)var;
		}
		virtual void OnDataVariableUpdated(BinaryView* view, const DataVariable& var)
		{
			(void)view;
			(void)var;
		}
		virtual void OnDataMetadataUpdated(BinaryView* view, uint64_t offset)
		{
			(void)view;
			(void)offset;
		}
		virtual void OnTagTypeUpdated(BinaryView* view, Ref<TagType> tagTypeRef)
		{
			(void)view;
			(void)tagTypeRef;
		}
		virtual void OnTagAdded(BinaryView* view, const TagReference& tagRef)
		{
			(void)view;
			(void)tagRef;
		}
		virtual void OnTagUpdated(BinaryView* view, const TagReference& tagRef)
		{
			(void)view;
			(void)tagRef;
		}
		virtual void OnTagRemoved(BinaryView* view, const TagReference& tagRef)
		{
			(void)view;
			(void)tagRef;
		}
		virtual void OnSymbolAdded(BinaryView* view, Symbol* sym)
		{
			(void)view;
			(void)sym;
		}
		virtual void OnSymbolUpdated(BinaryView* view, Symbol* sym)
		{
			(void)view;
			(void)sym;
		}
		virtual void OnSymbolRemoved(BinaryView* view, Symbol* sym)
		{
			(void)view;
			(void)sym;
		}
		virtual void OnStringFound(BinaryView* data, BNStringType type, uint64_t offset, size_t len)
		{
			(void)data;
			(void)type;
			(void)offset;
			(void)len;
		}
		virtual void OnStringRemoved(BinaryView* data, BNStringType type, uint64_t offset, size_t len)
		{
			(void)data;
			(void)type;
			(void)offset;
			(void)len;
		}
		virtual void OnTypeDefined(BinaryView* data, const QualifiedName& name, Type* type)
		{
			(void)data;
			(void)name;
			(void)type;
		}
		virtual void OnTypeUndefined(BinaryView* data, const QualifiedName& name, Type* type)
		{
			(void)data;
			(void)name;
			(void)type;
		}
		virtual void OnTypeReferenceChanged(BinaryView* data, const QualifiedName& name, Type* type)
		{
			(void)data;
			(void)name;
			(void)type;
		}
		virtual void OnTypeFieldReferenceChanged(BinaryView* data, const QualifiedName& name, uint64_t offset)
		{
			(void)data;
			(void)name;
			(void)offset;
		}
		virtual void OnSegmentAdded(BinaryView* data, Segment* segment)
		{
			(void)data;
			(void)segment;
		}
		virtual void OnSegmentUpdated(BinaryView* data, Segment* segment)
		{
			(void)data;
			(void)segment;
		}
		virtual void OnSegmentRemoved(BinaryView* data, Segment* segment)
		{
			(void)data;
			(void)segment;
		}
		virtual void OnSectionAdded(BinaryView* data, Section* section)
		{
			(void)data;
			(void)section;
		}
		virtual void OnSectionUpdated(BinaryView* data, Section* section)
		{
			(void)data;
			(void)section;
		}
		virtual void OnSectionRemoved(BinaryView* data, Section* section)
		{
			(void)data;
			(void)section;
		}

		/*! This notification is posted after the display name for a component is updated.

			\param data BinaryView the Component is contained in
		 	\param previousName Previous name of the component
			\param component The component which was modified.
		*/
		virtual void OnComponentNameUpdated(BinaryView* data, std::string& previousName, Component* component)
		{
			(void)data;
			(void)previousName;
			(void)component;
		}

		/*! This notification is posted after a Component is added to the tree.

		 	\param data BinaryView the Component was added to
		 	\param component Component which was added.
		*/
		virtual void OnComponentAdded(BinaryView* data, Component* component)
		{
			(void)data;
			(void)component;
		}

		/*! This notification is posted after a Component is removed from the tree.

		 	\param data BinaryView the Component was removed from
		 	\param formerParent Former parent of the Component
		 	\param component
		 	\parblock
		    The removed and now "dead" Component object.

		    This "dead" Component can no longer be moved to other components or have components added to it. It
		    should not be used after this point for storing any objects, and will be destroyed once no more references
		    are held to it.
		 	\endparblock
		*/
		virtual void OnComponentRemoved(BinaryView* data, Component* formerParent, Component* component)
		{
			(void)data;
			(void)formerParent;
			(void)component;
		}

		/*! This notification is posted whenever a component is moved from one component to another.

		    \param data BinaryView the Component was removed from
		    \param formerParent Former parent of the Component
		 	\param newParent New parent which the Component was moved to
		 	\param component The component that was moved.
		*/
		virtual void OnComponentMoved(BinaryView* data, Component* formerParent, Component* newParent, Component* component)
		{
			(void)data;
			(void)formerParent;
			(void)newParent;
			(void)component;
		}

		/*! This notification is posted whenever a Function is added to a Component

		 	\param data BinaryView containing the Component and Function
		 	\param component Component the Function was added to
		 	\param function The Function which was added
		*/
		virtual void OnComponentFunctionAdded(BinaryView* data, Component* component, Function* function)
		{
			(void)data;
			(void)component;
			(void)function;
		}

		/*! This notification is posted whenever a Function is removed from a Component

		 	\param data BinaryView containing the Component and Function
		 	\param component Component the Function was removed from
		 	\param function The Function which was removed
		*/
		virtual void OnComponentFunctionRemoved(BinaryView* data, Component* component, Function* function)
		{
			(void)data;
			(void)component;
			(void)function;
		}
	};

	/*!
		\ingroup fileaccessor
	*/
	class FileAccessor
	{
	  protected:
		BNFileAccessor m_callbacks;

	  private:
		static uint64_t GetLengthCallback(void* ctxt);
		static size_t ReadCallback(void* ctxt, void* dest, uint64_t offset, size_t len);
		static size_t WriteCallback(void* ctxt, uint64_t offset, const void* src, size_t len);

	  public:
		FileAccessor();
		FileAccessor(BNFileAccessor* accessor);
		virtual ~FileAccessor() {}

		BNFileAccessor* GetCallbacks() { return &m_callbacks; }

		virtual bool IsValid() const = 0;
		virtual uint64_t GetLength() const = 0;
		virtual size_t Read(void* dest, uint64_t offset, size_t len) = 0;
		virtual size_t Write(uint64_t offset, const void* src, size_t len) = 0;
	};

	/*!

		\ingroup fileaccessor
	*/
	class CoreFileAccessor : public FileAccessor
	{
	  public:
		CoreFileAccessor(BNFileAccessor* accessor);

		virtual bool IsValid() const override { return true; }
		virtual uint64_t GetLength() const override;
		virtual size_t Read(void* dest, uint64_t offset, size_t len) override;
		virtual size_t Write(uint64_t offset, const void* src, size_t len) override;
	};

	class Function;
	class BasicBlock;

	/*!

		\ingroup namelist
	*/
	class NameList
	{
	  protected:
		std::string m_join;
		std::vector<std::string> m_name;

	  public:
		NameList(const std::string& join);
		NameList(const std::string& name, const std::string& join);
		NameList(const std::vector<std::string>& name, const std::string& join);
		NameList(const NameList& name, const std::string& join);
		NameList(const NameList& name);
		virtual ~NameList();

		virtual NameList& operator=(const std::string& name);
		virtual NameList& operator=(const std::vector<std::string>& name);
		virtual NameList& operator=(const NameList& name);

		virtual bool operator==(const NameList& other) const;
		virtual bool operator!=(const NameList& other) const;
		virtual bool operator<(const NameList& other) const;
		virtual bool operator>(const NameList& other) const;

		virtual NameList operator+(const NameList& other) const;

		virtual std::string& operator[](size_t i);
		virtual const std::string& operator[](size_t i) const;
		virtual std::vector<std::string>::iterator begin();
		virtual std::vector<std::string>::iterator end();
		virtual std::vector<std::string>::const_iterator begin() const;
		virtual std::vector<std::string>::const_iterator end() const;
		virtual std::string& front();
		virtual const std::string& front() const;
		virtual std::string& back();
		virtual const std::string& back() const;
		virtual void insert(std::vector<std::string>::iterator loc, const std::string& name);
		virtual void insert(std::vector<std::string>::iterator loc, std::vector<std::string>::iterator b,
		    std::vector<std::string>::iterator e);
		virtual void erase(std::vector<std::string>::iterator i);
		virtual void clear();
		virtual void push_back(const std::string& name);
		virtual size_t size() const;
		virtual size_t StringSize() const;

		virtual std::string GetString(BNTokenEscapingType escaping = NoTokenEscapingType) const;
		virtual std::string GetJoinString() const { return m_join; }
		virtual bool IsEmpty() const { return m_name.size() == 0; }

		static std::string EscapeTypeName(const std::string& name, BNTokenEscapingType escaping);
		static std::string UnescapeTypeName(const std::string& name, BNTokenEscapingType escaping);

		BNNameList GetAPIObject() const;
		static void FreeAPIObject(BNNameList* name);
		static NameList FromAPIObject(BNNameList* name);
	};

	/*!

		\ingroup namelist
	*/
	class QualifiedName : public NameList
	{
	  public:
		QualifiedName();
		QualifiedName(const std::string& name);
		QualifiedName(const std::vector<std::string>& name);
		QualifiedName(const QualifiedName& name);
		virtual ~QualifiedName();

		virtual QualifiedName& operator=(const std::string& name);
		virtual QualifiedName& operator=(const std::vector<std::string>& name);
		virtual QualifiedName& operator=(const QualifiedName& name);
		virtual QualifiedName operator+(const QualifiedName& other) const;

		BNQualifiedName GetAPIObject() const;
		static void FreeAPIObject(BNQualifiedName* name);
		static QualifiedName FromAPIObject(const BNQualifiedName* name);
	};

	/*!

		\ingroup namelist
	*/
	class NameSpace : public NameList
	{
	  public:
		NameSpace();
		NameSpace(const std::string& name);
		NameSpace(const std::vector<std::string>& name);
		NameSpace(const NameSpace& name);
		virtual ~NameSpace();

		virtual NameSpace& operator=(const std::string& name);
		virtual NameSpace& operator=(const std::vector<std::string>& name);
		virtual NameSpace& operator=(const NameSpace& name);
		virtual NameSpace operator+(const NameSpace& other) const;

		virtual bool IsDefaultNameSpace() const;
		BNNameSpace GetAPIObject() const;
		static void FreeAPIObject(BNNameSpace* name);
		static NameSpace FromAPIObject(const BNNameSpace* name);
	};

	/*!
		\ingroup types
	*/
	class Symbol : public CoreRefCountObject<BNSymbol, BNNewSymbolReference, BNFreeSymbol>
	{
	  public:
		Symbol(BNSymbolType type, const std::string& shortName, const std::string& fullName, const std::string& rawName,
		    uint64_t addr, BNSymbolBinding binding = NoBinding,
		    const NameSpace& nameSpace = NameSpace(DEFAULT_INTERNAL_NAMESPACE), uint64_t ordinal = 0);
		Symbol(BNSymbolType type, const std::string& name, uint64_t addr, BNSymbolBinding binding = NoBinding,
		    const NameSpace& nameSpace = NameSpace(DEFAULT_INTERNAL_NAMESPACE), uint64_t ordinal = 0);
		Symbol(BNSymbol* sym);

		/*!
			Symbols are defined as one of the following types:

				=========================== ==============================================================
				BNSymbolType                Description
				=========================== ==============================================================
				FunctionSymbol              Symbol for function that exists in the current binary
				ImportAddressSymbol         Symbol defined in the Import Address Table
				ImportedFunctionSymbol      Symbol for a function that is not defined in the current binary
				DataSymbol                  Symbol for data in the current binary
				ImportedDataSymbol          Symbol for data that is not defined in the current binary
				ExternalSymbol              Symbols for data and code that reside outside the BinaryView
				LibraryFunctionSymbol       Symbols for external functions outside the library
				=========================== ==============================================================

		    \return Symbol type
		*/
		BNSymbolType GetType() const;

		/*!
		    \return Symbol binding
		*/
		BNSymbolBinding GetBinding() const;

		/*!
		    \return Symbol short name
		*/
		std::string GetShortName() const;

		/*!
		    \return Symbol full name
		*/
		std::string GetFullName() const;

		/*!
		    \return Symbol raw name
		*/
		std::string GetRawName() const;

		/*!
			\return Symbol Address
		*/
		uint64_t GetAddress() const;

		/*!
		    \return Symbol ordinal
		*/
		uint64_t GetOrdinal() const;

		/*!
		    \return Whether the symbol was auto-defined
		*/
		bool IsAutoDefined() const;

		/*!
		    \return Symbol NameSpace
		*/
		NameSpace GetNameSpace() const;

		static Ref<Symbol> ImportedFunctionFromImportAddressSymbol(Symbol* sym, uint64_t addr);
	};

	// TODO: This describes how the xref source references the target
	enum ReferenceType
	{
		UnspecifiedReferenceType = 0x0,
		ReadReferenceType = 0x1,
		WriteReferenceType = 0x2,
		ExecuteReferenceType = 0x4,

		// A type is referenced by a data variable
		DataVariableReferenceType = 0x8,

		// A type is referenced by another type
		DirectTypeReferenceType = 0x10,
		IndirectTypeReferenceType = 0x20,
	};

	// ReferenceSource describes code reference source; TypeReferenceSource describes type reference source.
	// When we query references, code references return vector<ReferenceSource>, data references return
	// vector<uint64_t>, type references return vector<TypeReferenceSource>.

	struct ReferenceSource
	{
		Ref<Function> func;
		Ref<Architecture> arch;
		uint64_t addr;
	};

	struct TypeFieldReference
	{
		Ref<Function> func;
		Ref<Architecture> arch;
		uint64_t addr;
		size_t size;
		Confidence<Ref<Type>> incomingType;
	};

	struct ILReferenceSource
	{
		Ref<Function> func;
		Ref<Architecture> arch;
		uint64_t addr;
		BNFunctionGraphType type;
		size_t exprId;
	};

	struct TypeReferenceSource
	{
		QualifiedName name;
		uint64_t offset;
		BNTypeReferenceType type;
	};


	class Tag;
	struct DisassemblyTextLineTypeInfo
	{
		bool hasTypeInfo;
		BinaryNinja::Ref<BinaryNinja::Type> parentType;
		size_t fieldIndex;
		uint64_t offset;

		DisassemblyTextLineTypeInfo() : hasTypeInfo(false), parentType(nullptr), fieldIndex(-1), offset(0) {}
	};

	struct DisassemblyTextLine
	{
		uint64_t addr;
		size_t instrIndex;
		std::vector<InstructionTextToken> tokens;
		BNHighlightColor highlight;
		std::vector<Ref<Tag>> tags;
		DisassemblyTextLineTypeInfo typeInfo;

		DisassemblyTextLine();
	};

	/*!
		\ingroup lineardisassembly
	*/
	struct LinearDisassemblyLine
	{
		BNLinearDisassemblyLineType type;
		Ref<Function> function;
		Ref<BasicBlock> block;
		DisassemblyTextLine contents;

		static LinearDisassemblyLine FromAPIObject(BNLinearDisassemblyLine* line);
	};

	struct TypeDefinitionLine
	{
		BNTypeDefinitionLineType lineType;
		std::vector<InstructionTextToken> tokens;
		Ref<Type> type, rootType;
		std::string rootTypeName;
		uint64_t offset;
		size_t fieldIndex;

		static TypeDefinitionLine FromAPIObject(BNTypeDefinitionLine* line);
		static BNTypeDefinitionLine* CreateTypeDefinitionLineList(
		    const std::vector<TypeDefinitionLine>& lines);
		static void FreeTypeDefinitionLineList(
		    BNTypeDefinitionLine* lines, size_t count);
	};

	class DisassemblySettings;

	/*!
		\ingroup binaryview
	*/
	class AnalysisCompletionEvent :
	    public CoreRefCountObject<BNAnalysisCompletionEvent, BNNewAnalysisCompletionEventReference,
	        BNFreeAnalysisCompletionEvent>
	{
	  protected:
		std::function<void()> m_callback;
		std::recursive_mutex m_mutex;

		static void CompletionCallback(void* ctxt);

	  public:
		AnalysisCompletionEvent(BinaryView* view, const std::function<void()>& callback);
		void Cancel();
	};

	/*!
		\ingroup binaryview
	*/
	struct ActiveAnalysisInfo
	{
		Ref<Function> func;
		uint64_t analysisTime;
		size_t updateCount;
		size_t submitCount;

		ActiveAnalysisInfo(Ref<Function> f, uint64_t t, size_t uc, size_t sc) :
		    func(f), analysisTime(t), updateCount(uc), submitCount(sc)
		{}
	};

	/*!
		\ingroup binaryview
	*/
	struct AnalysisInfo
	{
		BNAnalysisState state;
		uint64_t analysisTime;
		std::vector<ActiveAnalysisInfo> activeInfo;
	};

	/*!
		\ingroup binaryview
	*/
	struct DataVariable
	{
		DataVariable() {}
		DataVariable(uint64_t a, Type* t, bool d) : address(a), type(t), autoDiscovered(d) {}

		uint64_t address;
		Confidence<Ref<Type>> type;
		bool autoDiscovered;
	};

	/*!
		\ingroup binaryview
	*/
	struct DataVariableAndName
	{
		DataVariableAndName() {}
		DataVariableAndName(uint64_t a, Type* t, bool d, const std::string& n) :
		    address(a), type(t), autoDiscovered(d), name(n)
		{}

		uint64_t address;
		Confidence<Ref<Type>> type;
		bool autoDiscovered;
		std::string name;
	};

	/*!
		\ingroup binaryview
	*/
	class TagType : public CoreRefCountObject<BNTagType, BNNewTagTypeReference, BNFreeTagType>
	{
	  public:
		typedef BNTagTypeType Type;

		TagType(BNTagType* tagType);
		TagType(BinaryView* view);
		TagType(BinaryView* view, const std::string& name, const std::string& icon, bool visible = true,
		    Type type = UserTagType);

		/*!
			\return BinaryView for this TagType
		*/
		BinaryView* GetView() const;

		/*!
		    \return Unique ID of the TagType
		*/
		std::string GetId() const;

		/*!
		    \return Name of the TagType
		*/
		std::string GetName() const;

		/*!
		    Set the name of the TagType

		    \param name New name
		*/
		void SetName(const std::string& name);

		/*!
		    \return Unicode string containing an emoji to be used as an icon
		*/
		std::string GetIcon() const;

		/*!
		    Set the icon to be used for a TagType

		    \param icon Unicode string containing an emoji to be used as an icon
		*/
		void SetIcon(const std::string& icon);

		/*!
		    \return Whether the tags of this type are visible
		*/
		bool GetVisible() const;

		/*!
		    Set whether the tags of this type are visible

		    \param visible Whether the tags of this type are visible
		*/
		void SetVisible(bool visible);

		/*!
			One of: UserTagType, NotificationTagType, BookmarksTagType

			\return Tag Type.
		*/
		Type GetType() const;

		/*!
		    \param type Tag Type. One of: UserTagType, NotificationTagType, BookmarksTagType
		*/
		void SetType(Type type);
	};

	class Tag : public CoreRefCountObject<BNTag, BNNewTagReference, BNFreeTag>
	{
	  public:
		Tag(BNTag* tag);
		Tag(Ref<TagType> type, const std::string& data = "");

		/*!
		    \return Unique ID of the Tag
		*/
		std::string GetId() const;

		/*!
		    \return TagType of this tag
		*/
		Ref<TagType> GetType() const;
		std::string GetData() const;
		void SetData(const std::string& data);

		static BNTag** CreateTagList(const std::vector<Ref<Tag>>& tags, size_t* count);
		static std::vector<Ref<Tag>> ConvertTagList(BNTag** tags, size_t count);
		static std::vector<Ref<Tag>> ConvertAndFreeTagList(BNTag** tags, size_t count);
	};

	class Architecture;
	class Function;

	/*!
		\ingroup binaryview
	*/
	struct TagReference
	{
		typedef BNTagReferenceType RefType;

		RefType refType;
		bool autoDefined;
		Ref<Tag> tag;
		Ref<Architecture> arch;
		Ref<Function> func;
		uint64_t addr;

		TagReference();
		TagReference(const BNTagReference& ref);

		bool operator==(const TagReference& other) const;
		bool operator!=(const TagReference& other) const;

		operator BNTagReference() const;

		static BNTagReference* CreateTagReferenceList(const std::vector<TagReference>& tags, size_t* count);
		static std::vector<TagReference> ConvertTagReferenceList(BNTagReference* tags, size_t count);
		static std::vector<TagReference> ConvertAndFreeTagReferenceList(BNTagReference* tags, size_t count);
	};

	class Relocation;

	/*! The Segment object is returned during BinaryView creation and should not be directly instantiated.

		\ingroup binaryview
	*/
	class Segment : public CoreRefCountObject<BNSegment, BNNewSegmentReference, BNFreeSegment>
	{
	  public:
		Segment(BNSegment* seg);
		uint64_t GetStart() const;
		uint64_t GetLength() const;
		uint64_t GetEnd() const;
		uint64_t GetDataEnd() const;
		uint64_t GetDataOffset() const;
		uint64_t GetDataLength() const;
		uint32_t GetFlags() const;
		bool IsAutoDefined() const;

		std::vector<std::pair<uint64_t, uint64_t>> GetRelocationRanges() const;
		std::vector<std::pair<uint64_t, uint64_t>> GetRelocationRangesAtAddress(uint64_t addr) const;
		std::vector<Ref<Relocation>> GetRelocationsInRange(uint64_t addr, uint64_t size) const;
		uint64_t GetRelocationsCount() const;

		void SetLength(uint64_t length);
		void SetDataOffset(uint64_t dataOffset);
		void SetDataLength(uint64_t dataLength);
		void SetFlags(uint32_t flags);
	};

	/*! The Section object is returned during BinaryView creation and should not be directly instantiated.

		\ingroup binaryview
	*/
	class Section : public CoreRefCountObject<BNSection, BNNewSectionReference, BNFreeSection>
	{
	  public:
		Section(BNSection* sec);
		Section(const std::string& name, uint64_t start, uint64_t length, BNSectionSemantics semantics,
		    const std::string& type, uint64_t align, uint64_t entrySize, const std::string& linkedSection,
		    const std::string& infoSection, uint64_t infoData, bool autoDefined);
		std::string GetName() const;
		std::string GetType() const;
		uint64_t GetStart() const;
		uint64_t GetLength() const;
		uint64_t GetInfoData() const;
		uint64_t GetAlignment() const;
		uint64_t GetEntrySize() const;
		std::string GetLinkedSection() const;
		std::string GetInfoSection() const;
		BNSectionSemantics GetSemantics() const;
		bool AutoDefined() const;
	};

	struct QualifiedNameAndType;
	struct PossibleValueSet;
	class Metadata;
	class Structure;
	class NamedTypeReference;
	struct TypeParserResult;
	class Component;
	class DebugInfo;

	class QueryMetadataException : public std::exception
	{
		const std::string m_error;

	  public:
		QueryMetadataException(const std::string& error) : std::exception(), m_error(error) {}
		virtual const char* what() const NOEXCEPT { return m_error.c_str(); }
	};

	/*! \c BinaryView implements a view on binary data, and presents a queryable interface of a binary file.

		One key job of BinaryView is file format parsing which allows Binary Ninja to read, write, insert, remove portions
		of the file given a virtual address. For the purposes of this documentation we define a virtual address as the
		memory address that the various pieces of the physical file will be loaded at.

		A binary file does not have to have just one BinaryView, thus much of the interface to manipulate disassembly exists
		within or is accessed through a BinaryView. All files are guaranteed to have at least the \c Raw BinaryView. The
		\c Raw BinaryView is simply a hex editor, but is helpful for manipulating binary files via their absolute addresses.

		BinaryViews are plugins and thus registered with Binary Ninja at startup, and thus should **never** be instantiated
		directly as this is already done. The list of available BinaryViews can be seen in the BinaryViewType class which
		provides an iterator and map of the various installed BinaryViews:

		\code{.cpp}
		// Getting a list of valid BinaryViewTypes
		vector<Ref<BinaryViewType>> types = BinaryViewType::GetViewTypes()

		// Getting a list of valid BinaryViewTypes valid for given data
		vector<Ref<BinaryViewType>> types = BinaryViewType::GetViewTypesForData(bv);

		Ref<BinaryViewType> machoType = BinaryViewType::GetByName("Mach-O");
		\endcode

		\see BinaryViewType

		\b In the python console:
		\code{.py}
		>>> list(BinaryViewType)
		[<view type: 'Raw'>, <view type: 'ELF'>, <view type: 'Mach-O'>, <view type: 'PE'>]
		>>> BinaryViewType['ELF']
		<view type: 'ELF'>
		\endcode

		To open a file with a given BinaryView the following code is recommended:

		\code{.cpp}
		auto bv = OpenView("/bin/ls");
		\endcode

		\remark By convention in the rest of this document we will use bv to mean an open and, analyzed, BinaryView of an executable file.

		When a BinaryView is open on an executable view analysis is automatically run unless specific named parameters are used
		to disable updates. If such a parameter is used, updates can be triggered using the \c UpdateAnalysisAndWait() method
		which disassembles the executable and returns when all disassembly and analysis is complete:

		\code{.cpp}
		bv->UpdateAnalysisAndWait();
		\endcode

		Since BinaryNinja's analysis is multi-threaded this can also be done in the background
		by using the \c UpdateAnalysis method instead.

		\note An important note on the \c \*User\*() methods. Binary Ninja makes a distinction between edits
		performed by the user and actions performed by auto analysis.  Auto analysis actions that can quickly be recalculated
		are not saved to the database. Auto analysis actions that take a long time and all user edits are stored in the
		database (e.g. \c RemoveUserFunction rather than \c RemoveFunction ). Thus use \c \*User\*() methods if saving
		to the database is desired.

		\ingroup binaryview
	*/
	class BinaryView : public CoreRefCountObject<BNBinaryView, BNNewViewReference, BNFreeBinaryView>
	{
	  protected:
		Ref<FileMetadata> m_file;  //!< The underlying file

		/*! BinaryView constructor
		   \param typeName name of the BinaryView (e.g. ELF, PE, Mach-O, ...)
		   \param file a file to create a view from
		   \param parentView optional view that contains the raw data used by this view
		*/
		BinaryView(const std::string& typeName, FileMetadata* file, BinaryView* parentView = nullptr);

		/*! PerformRead provides a mapping between the flat file and virtual offsets in the file.

		    \note This method **may** be overridden by custom BinaryViews. Use AddAutoSegment to provide
		    	  data without overriding this method.

			\warning This method **must not** be called directly.

		    \param dest the address to write len number of bytes.
		    \param offset the virtual offset to find and read len bytes from
		    \param len the number of bytes to read from offset and write to dest
		*/
		virtual size_t PerformRead(void* dest, uint64_t offset, size_t len)
		{
			(void)dest;
			(void)offset;
			(void)len;
			return 0;
		}

		/*! PerformWrite provides a mapping between the flat file and virtual offsets in the file.

		    \note This method **may** be overridden by custom BinaryViews. Use AddAutoSegment to provide
		          data without overriding this method.

			\warning This method **must not** be called directly.
		    \param offset the virtual offset to find and write len bytes to
		    \param data the address to read len number of bytes from
		    \param len the number of bytes to read from data and write to offset
		    \return length of data written, 0 on error
		*/
		virtual size_t PerformWrite(uint64_t offset, const void* data, size_t len)
		{
			(void)offset;
			(void)data;
			(void)len;
			return 0;
		}

		/*! PerformInsert provides a mapping between the flat file and virtual offsets in the file,
				inserting `len` bytes from `data` to virtual address `offset`

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset the virtual offset to find and insert len bytes into
		    \param data the address to read len number of bytes from
		    \param len the number of bytes to read from data and insert at offset
		    \return length of data inserted, 0 on error
		*/
		virtual size_t PerformInsert(uint64_t offset, const void* data, size_t len)
		{
			(void)offset;
			(void)data;
			(void)len;
			return 0;
		}

		/*! PerformRemove provides a mapping between the flat file and virtual offsets in the file,
		    	removing `len` bytes from virtual address `offset`

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

			\param offset the virtual offset to find and remove bytes from
		    \param len the number of bytes to be removed
		    \return length of data removed, 0 on error
		*/
		virtual size_t PerformRemove(uint64_t offset, uint64_t len)
		{
			(void)offset;
			(void)len;
			return 0;
		}

		/*! PerformGetModification implements a query as to whether the virtual address `offset` is modified.

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset a virtual address to be checked
		    \return one of Original, Changed, Inserted
		*/
		virtual BNModificationStatus PerformGetModification(uint64_t offset)
		{
			(void)offset;
			return Original;
		}

		/*! PerformIsValidOffset implements a check as to whether a virtual address `offset` is valid

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset the virtual address to check
		    \return whether the offset is valid
		*/
		virtual bool PerformIsValidOffset(uint64_t offset);

		/*! PerformIsOffsetReadable implements a check as to whether a virtual address is readable

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset the virtual address to check
		    \return whether the offset is readable
		*/
		virtual bool PerformIsOffsetReadable(uint64_t offset);

		/*! PerformIsOffsetWritable implements a check as to whether a virtual address is writable

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset the virtual address to check
		    \return whether the offset is writable
		*/
		virtual bool PerformIsOffsetWritable(uint64_t offset);

		/*! PerformIsOffsetExecutable implements a check as to whether a virtual address is executable

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset the virtual address to check
		    \return whether the offset is executable
		*/
		virtual bool PerformIsOffsetExecutable(uint64_t offset);

		/*! PerformIsOffsetBackedByFile implements a check as to whether a virtual address is backed by a file

		    \param offset the virtual address to check
		    \return whether the offset is backed by a file
		*/
		virtual bool PerformIsOffsetBackedByFile(uint64_t offset);

		/*! PerformGetNextValidOffset implements a query for the next valid readable, writable, or executable virtual memory address after `offset`

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset a virtual address to start checking from
		    \return the next valid address
		*/
		virtual uint64_t PerformGetNextValidOffset(uint64_t offset);

		/*! PerformGetStart implements a query for the first readable, writable, or executable virtual address in the BinaryView

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \return the first virtual address in the BinaryView
		*/
		virtual uint64_t PerformGetStart() const { return 0; }
		virtual uint64_t PerformGetLength() const { return 0; }
		virtual uint64_t PerformGetEntryPoint() const { return 0; }

		/*! PerformIsExecutable implements a check which returns true if the BinaryView is executable.

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \return whether the BinaryView is executable
		*/
		virtual bool PerformIsExecutable() const { return false; }

		/*! PerformGetDefaultEndianness implements a check which returns the Endianness of the BinaryView

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \return either LittleEndian or BigEndian
		*/
		virtual BNEndianness PerformGetDefaultEndianness() const;

		/*! PerformIsRelocatable implements a check which returns true if the BinaryView is relocatable.

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \return whether the BinaryView is relocatable
		*/
		virtual bool PerformIsRelocatable() const;

		/*! PerformGetAddressSize implements a query for the address size for this BinaryView

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \return the address size for this BinaryView
		*/
		virtual size_t PerformGetAddressSize() const;

		virtual bool PerformSave(FileAccessor* file);
		void PerformDefineRelocation(Architecture* arch, BNRelocationInfo& info, uint64_t target, uint64_t reloc);
		void PerformDefineRelocation(Architecture* arch, BNRelocationInfo& info, Ref<Symbol> sym, uint64_t reloc);
		void NotifyDataWritten(uint64_t offset, size_t len);
		void NotifyDataInserted(uint64_t offset, size_t len);
		void NotifyDataRemoved(uint64_t offset, uint64_t len);

	  private:
		static bool InitCallback(void* ctxt);
		static void FreeCallback(void* ctxt);
		static size_t ReadCallback(void* ctxt, void* dest, uint64_t offset, size_t len);
		static size_t WriteCallback(void* ctxt, uint64_t offset, const void* src, size_t len);
		static size_t InsertCallback(void* ctxt, uint64_t offset, const void* src, size_t len);
		static size_t RemoveCallback(void* ctxt, uint64_t offset, uint64_t len);
		static BNModificationStatus GetModificationCallback(void* ctxt, uint64_t offset);
		static bool IsValidOffsetCallback(void* ctxt, uint64_t offset);
		static bool IsOffsetReadableCallback(void* ctxt, uint64_t offset);
		static bool IsOffsetWritableCallback(void* ctxt, uint64_t offset);
		static bool IsOffsetExecutableCallback(void* ctxt, uint64_t offset);
		static bool IsOffsetBackedByFileCallback(void* ctxt, uint64_t offset);
		static uint64_t GetNextValidOffsetCallback(void* ctxt, uint64_t offset);
		static uint64_t GetStartCallback(void* ctxt);
		static uint64_t GetLengthCallback(void* ctxt);
		static uint64_t GetEntryPointCallback(void* ctxt);
		static bool IsExecutableCallback(void* ctxt);
		static BNEndianness GetDefaultEndiannessCallback(void* ctxt);
		static bool IsRelocatableCallback(void* ctxt);
		static size_t GetAddressSizeCallback(void* ctxt);
		static bool SaveCallback(void* ctxt, BNFileAccessor* file);

	  public:
		BinaryView(BNBinaryView* view);

		virtual bool Init() { return true; }


		/*!
			\return FileMetadata for this BinaryView
		*/
		FileMetadata* GetFile() const { return m_file; }

		/*!
		    \return View that contains the raw data used by this view
		*/
		Ref<BinaryView> GetParentView() const;
		std::string GetTypeName() const;

		/*!
			\return Whether the file has unsaved modifications
		*/
		bool IsModified() const;

		/*!
			\return Whether auto-analysis results have changed.
		*/
		bool IsAnalysisChanged() const;

		/*! Writes the current database (.bndb) out to the specified file.

		 	\param path path and filename to write the bndb to. Should have ".bndb" appended to it.
		 	\param settings Special save options
		 	\return Whether the save was successful
		*/
		bool CreateDatabase(const std::string& path, Ref<SaveSettings> settings = new SaveSettings());

		/*! Writes the current database (.bndb) out to the specified file.

		    \param path path and filename to write the bndb to. Should have ".bndb" appended to it.
		    \param progressCallback callback function to send save progress to.
		    \param settings Special save options
		    \return Whether the save was successful
		*/
		bool CreateDatabase(const std::string& path,
		    const std::function<bool(size_t progress, size_t total)>& progressCallback,
		    Ref<SaveSettings> settings = new SaveSettings());
		bool SaveAutoSnapshot(Ref<SaveSettings> settings = new SaveSettings());
		bool SaveAutoSnapshot(const std::function<bool(size_t progress, size_t total)>& progressCallback,
		    Ref<SaveSettings> settings = new SaveSettings());

		/*! Start recording actions taken so they can be undone at some point
		*/
		void BeginUndoActions();
		void AddUndoAction(UndoAction* action);

		/*!  Commit the actions taken since the last commit to the undo database.
		*/
		void CommitUndoActions();

		/*!
			\return Whether it is possible to perform an Undo
		*/
		bool CanUndo();

		/*! Undo the last committed action in the undo database.
		*/
		bool Undo();

		/*!
			\return Whether it is possible to perform a Redo
		*/
		bool CanRedo();

		/*! Redo the last committed action in the undo database.
		*/
		bool Redo();

		/*!
		    Get the current View name, e.g. ``Linear:ELF``, ``Graph:PE``

		    \return The current view name
		*/
		std::string GetCurrentView();

		/*!
		    Get the current offset in the current view

		    \return The current offset
		*/
		uint64_t GetCurrentOffset();

		/*!
			Navigate to the specified virtual address in the specified view

		 	\param view View name. e.g. ``Linear:ELF``, ``Graph:PE``
		 	\param offset Virtual address to navigate to
		 	\return Whether the navigation was successful.
		*/
		bool Navigate(const std::string& view, uint64_t offset);

		/*! Read writes `len` bytes at virtual address `offset` to address `dest`

		    \param dest Virtual address to write to
		    \param offset virtual address to read from
		    \param len number of bytes to read
		    \return amount of bytes read
		*/
		size_t Read(void* dest, uint64_t offset, size_t len);

		/*! ReadBuffer reads len bytes from a virtual address into a DataBuffer

		    \param offset virtual address to read from
		    \param len number of bytes to read
		    \return DataBuffer containing the read bytes
		*/
		DataBuffer ReadBuffer(uint64_t offset, size_t len);

		/*! Write writes `len` bytes data at address `dest` to virtual address `offset`

			\param offset virtual address to write to
			\param data address to read from
			\param len number of bytes to write
			\return amount of bytes written
		*/
		size_t Write(uint64_t offset, const void* data, size_t len);

		/*! WriteBuffer writes the contents of a DataBuffer into a virtual address

			\param offset virtual address to write to
		    \param data DataBuffer containing the bytes to write
		    \return amount of bytes written
		*/
		size_t WriteBuffer(uint64_t offset, const DataBuffer& data);

		/*! Insert inserts `len` bytes data at address `dest` starting from virtual address `offset`

			\param offset virtual address to start inserting from
			\param data address to read from
			\param len number of bytes to write
			\return amount of bytes written
		*/
		size_t Insert(uint64_t offset, const void* data, size_t len);

		/*! InsertBuffer inserts the contents of a DataBuffer starting from a virtual address

			\param offset virtual address to start inserting from
		    \param data DataBuffer containing the bytes to write
		    \return amount of bytes written
		*/
		size_t InsertBuffer(uint64_t offset, const DataBuffer& data);

		/*! PerformRemove removes `len` bytes from virtual address `offset`

			\param offset the virtual offset to find and remove bytes from
		    \param len the number of bytes to be removed
		    \return length of data removed, 0 on error
		*/
		size_t Remove(uint64_t offset, uint64_t len);

		std::vector<float> GetEntropy(uint64_t offset, size_t len, size_t blockSize);

		/*! GetModification checks whether the virtual address `offset` is modified.

		    \param offset a virtual address to be checked
		    \return one of Original, Changed, Inserted
		*/
		BNModificationStatus GetModification(uint64_t offset);
		std::vector<BNModificationStatus> GetModification(uint64_t offset, size_t len);

		/*! IsValidOffset checks whether a virtual address `offset` is valid

		    \param offset the virtual address to check
		    \return whether the offset is valid
		*/
		bool IsValidOffset(uint64_t offset) const;

		/*! IsOffsetReadable checks whether a virtual address is readable

		    \param offset the virtual address to check
		    \return whether the offset is readable
		*/
		bool IsOffsetReadable(uint64_t offset) const;

		/*! IsOffsetWritable checks whether a virtual address is writable

		    \param offset the virtual address to check
		    \return whether the offset is writable
		*/
		bool IsOffsetWritable(uint64_t offset) const;

		/*! IsOffsetExecutable checks whether a virtual address is executable

		    \param offset the virtual address to check
		    \return whether the offset is executable
		*/
		bool IsOffsetExecutable(uint64_t offset) const;

		/*! IsOffsetBackedByFile checks whether a virtual address is backed by a file

		    \param offset the virtual address to check
		    \return whether the offset is backed by a file
		*/
		bool IsOffsetBackedByFile(uint64_t offset) const;
		bool IsOffsetCodeSemantics(uint64_t offset) const;
		bool IsOffsetWritableSemantics(uint64_t offset) const;
		bool IsOffsetExternSemantics(uint64_t offset) const;

		/*! GetNextValidOffset implements a query for the next valid readable, writable, or executable virtual memory address after `offset`

		    \param offset a virtual address to start checking from
		    \return the next valid address
		*/
		uint64_t GetNextValidOffset(uint64_t offset) const;

		/*! GetStart queries for the first valid virtual address in the BinaryView

		    \return the start of the BinaryView
		*/
		uint64_t GetStart() const;

		/*! GetEnd queries for the first valid virtual address in the BinaryView

		    \return the end of the BinaryView
		*/
		uint64_t GetEnd() const;

		/*! GetLength queries for the total length of the BinaryView from start to end

		    \return the length of the BinaryView
		*/
		uint64_t GetLength() const;

		/*! GetEntryPoint returns the entry point of the executable in the BinaryView
					    \return the entry point
		*/
		uint64_t GetEntryPoint() const;

		/*! GetDefaultArchitecture returns the current "default architecture" for the BinaryView

		    \return the current default architecture
		*/
		Ref<Architecture> GetDefaultArchitecture() const;

		/*! SetDefaultArchitecture allows setting the default architecture for the BinaryView

		    \param arch the new default architecture
		*/
		void SetDefaultArchitecture(Architecture* arch);

		/*! GetDefaultPlatform returns the current default platform for the BinaryView

		    \return the current default Platform
		*/
		Ref<Platform> GetDefaultPlatform() const;

		/*! SetDefaultPlatform allows setting the default platform for the BinaryView

		    \param arch the new default platform
		*/
		void SetDefaultPlatform(Platform* platform);

		/*! GetDefaultEndianness returns the default endianness for the BinaryView

		    \return the current default Endianness, one of LittleEndian, BigEndian
		*/
		BNEndianness GetDefaultEndianness() const;

		/*! Whether the binary is relocatable

		    \return Whether the binary is relocatable
		*/
		bool IsRelocatable() const;

		/*! Address size of the binary

		    \return Address size of the binary
		*/
		size_t GetAddressSize() const;

		/*! Whether the binary is an executable

		    \return Whether the binary is an executable
		*/
		bool IsExecutable() const;

		/*! Save the original binary file to a FileAccessor

		    \param file a FileAccessor pointing to the location to save the binary
		    \return Whether the save was successful
		*/
		bool Save(FileAccessor* file);

		/*! Save the original binary file to the provided destination

		    \param path destination path and filename of the file to be written
		    \return Whether the save was successful
		*/
		bool Save(const std::string& path);

		void DefineRelocation(Architecture* arch, BNRelocationInfo& info, uint64_t target, uint64_t reloc);
		void DefineRelocation(Architecture* arch, BNRelocationInfo& info, Ref<Symbol> target, uint64_t reloc);
		std::vector<std::pair<uint64_t, uint64_t>> GetRelocationRanges() const;
		std::vector<std::pair<uint64_t, uint64_t>> GetRelocationRangesAtAddress(uint64_t addr) const;
		bool RangeContainsRelocation(uint64_t addr, size_t size) const;

		/*! Provides a mechanism for receiving callbacks for various analysis events.

		    \param notify An instance of a class Subclassing BinaryDataNotification
		*/
		void RegisterNotification(BinaryDataNotification* notify);

		/*! Unregister a notification passed to RegisterNotification

		    \param notify An instance of a class Subclassing BinaryDataNotification
		*/
		void UnregisterNotification(BinaryDataNotification* notify);

		/*! Adds an analysis option. Analysis options elaborate the analysis phase. The user must start analysis by calling either UpdateAnalysis or UpdateAnalysisAndWait

		    \param name Name of the analysis option. Available options are "linearsweep" and "signaturematcher"
		*/
		void AddAnalysisOption(const std::string& name);

		/*! Add a new function of the given platform at the virtual address

		    \param platform Platform for the function to be loaded
		    \param addr Virtual adddress of the function to be loaded
		*/
		void AddFunctionForAnalysis(Platform* platform, uint64_t addr);

		/*! adds an virtual address to start analysis from for a given platform

		    \param platform Platform for the entry point analysis
		    \param start virtual address to start analysis from
		*/
		void AddEntryPointForAnalysis(Platform* platform, uint64_t start);

		/*! removes a function from the list of functions

		    \param func Function to be removed
		*/
		void RemoveAnalysisFunction(Function* func);

		/*! Add a new user function of the given platform at the virtual address

			\param platform Platform for the function to be loaded
		    \param addr Virtual adddress of the function to be loaded
		*/
		void CreateUserFunction(Platform* platform, uint64_t start);

		/*! removes a user function from the list of functions

		    \param func Function to be removed
		*/
		void RemoveUserFunction(Function* func);

		/*! check for the presence of an initial analysis in this BinaryView.

		    \return Whether the BinaryView has an initial analysis
		*/
		bool HasInitialAnalysis();

		/*! Controls the analysis hold for this BinaryView. Enabling analysis hold defers all future
		 	analysis updates, therefore causing UpdateAnalysis and UpdateAnalysisAndWait to take no action.

		    \param enable Whether to enable or disable the analysis hold
		*/
		void SetAnalysisHold(bool enable);

		/*! start the analysis running and dont return till it is complete

			Analysis of BinaryViews does not occur automatically, the user must start analysis by calling either
		 	UpdateAnalysis or UpdateAnalysisAndWait. An analysis update **must** be run after changes are made which could change
		    analysis results such as adding functions.
		*/
		void UpdateAnalysisAndWait();

		/*! asynchronously starts the analysis running and returns immediately.

			Analysis of BinaryViews does not occur automatically, the user must start analysis by calling either
		 	UpdateAnalysis or UpdateAnalysisAndWait. An analysis update **must** be run after changes are made which could change
		    analysis results such as adding functions.
		*/
		void UpdateAnalysis();

		/*! Abort the currently running analysis

			This method should be considered non-recoverable and generally only used when shutdown is imminent after stopping.
		*/
		void AbortAnalysis();

		/*! Define a DataVariable at a given address with a set type

		    \param addr virtual address to define the DataVariable at
		    \param type Type for the DataVariable
		*/
		void DefineDataVariable(uint64_t addr, const Confidence<Ref<Type>>& type);

		/*! Define a user DataVariable at a given address with a set type

		    \param addr virtual address to define the DataVariable at
		    \param type Type for the DataVariable
		*/
		void DefineUserDataVariable(uint64_t addr, const Confidence<Ref<Type>>& type);

		/*! Undefine a DataVariable at a given address

		    \param addr virtual address of the DataVariable
		*/
		void UndefineDataVariable(uint64_t addr);

		/*! Undefine a user DataVariable at a given address

		    \param addr virtual address of the DataVariable
		*/
		void UndefineUserDataVariable(uint64_t addr);

		/*! Get a map of DataVariables defined in the current BinaryView

		    \return A map of addresses to the DataVariables defined at them
		*/
		std::map<uint64_t, DataVariable> GetDataVariables();

		/*! Get a DataVariable at a given address

		    \param addr Address for the DataVariable
		    \param var Reference to a DataVariable class to write to
		    \return Whether a DataVariable was successfully retrieved
		*/
		bool GetDataVariableAtAddress(uint64_t addr, DataVariable& var);

		/*! Get a list of functions within this BinaryView

		    \return vector of Functions within the BinaryView
		*/
		std::vector<Ref<Function>> GetAnalysisFunctionList();

		/*! Check whether the BinaryView has any functions defined

		    \return Whether the BinaryView has any functions defined
		*/
		bool HasFunctions() const;


		/*! Gets a function object for the function starting at a virtual address

		    \param platform Platform for the desired function
		    \param addr Starting virtual address for the function
		    \return the Function, if it exists
		*/
		Ref<Function> GetAnalysisFunction(Platform* platform, uint64_t addr);

		/*! Get the most recently used Function starting at a virtual address

		    \param addr Starting virtual address for the function
		    \return the Function, if it exists
		*/
		Ref<Function> GetRecentAnalysisFunctionForAddress(uint64_t addr);

		/*! Get a list of functions defined at an address

		    \param addr Starting virtual address for the function
		    \return vector of functions
		*/
		std::vector<Ref<Function>> GetAnalysisFunctionsForAddress(uint64_t addr);

		/*! Get a list of functions containing an address

		    \param addr Address to check
		    \return vector of Functions
		*/
		std::vector<Ref<Function>> GetAnalysisFunctionsContainingAddress(uint64_t addr);

		/*! Get the function defined as the Analysis entry point for the view

		    \return The analysis entry point function
		*/
		Ref<Function> GetAnalysisEntryPoint();


		/*! Get most recently used Basic Block containing a virtual address

		    \param addr Address within the BasicBlock
		    \return The BasicBlock if it exists
		*/
		Ref<BasicBlock> GetRecentBasicBlockForAddress(uint64_t addr);

		/*! Get a list of Basic Blocks containing a virtual address

		    \param addr Address to check
		    \return vector of basic blocks containing that address
		*/
		std::vector<Ref<BasicBlock>> GetBasicBlocksForAddress(uint64_t addr);

		/*! Get a list of basic blocks starting at a virtual address

		    \param addr Address to check
		    \return vector of basic blocks starting at that address
		*/
		std::vector<Ref<BasicBlock>> GetBasicBlocksStartingAtAddress(uint64_t addr);

		/*! Get Code References to a virtual address

		    \param addr Address to check
		    \return vector of ReferenceSources referencing the virtual address
		*/
		std::vector<ReferenceSource> GetCodeReferences(uint64_t addr);

		/*! Get Code References to a virtual address

		    \param addr Address to check
		    \param len Length of query
		    \return vector of ReferenceSources referencing the virtual address range
		*/
		std::vector<ReferenceSource> GetCodeReferences(uint64_t addr, uint64_t len);

		/*! Get code references from a ReferenceSource

		    \param src reference source
		    \return List of virtual addresses referenced by this source
		*/
		std::vector<uint64_t> GetCodeReferencesFrom(ReferenceSource src);

		/*! Get code references from a ReferenceSource

		    \param src reference source
		    \param len Length of query
		    \return List of virtual addresses referenced by this source
		*/
		std::vector<uint64_t> GetCodeReferencesFrom(ReferenceSource src, uint64_t len);

		/*! Get Data References to a virtual address

		    \param addr Address to check
		    \return vector of virtual addresses referencing the virtual address
		*/
		std::vector<uint64_t> GetDataReferences(uint64_t addr);

		/*! Get Data References to a virtual address

		    \param addr Address to check
		    \param len Length of query
		    \return vector of virtual addresses referencing the virtual address range
		*/
		std::vector<uint64_t> GetDataReferences(uint64_t addr, uint64_t len);

		/*! Get Data references from a virtual address

		    \param src reference source
		    \return List of virtual addresses referenced by this address
		*/
		std::vector<uint64_t> GetDataReferencesFrom(uint64_t addr);

		/*! Get Data references from a virtual address

		    \param src reference source
		    \param len Length of query
		    \return List of virtual addresses referenced by this address
		*/
		std::vector<uint64_t> GetDataReferencesFrom(uint64_t addr, uint64_t len);

		/*! Add a user Data Reference from a virtual address to another virtual address

		    \param fromAddr Address referencing the toAddr value
		    \param toAddr virtual address being referenced
		*/
		void AddUserDataReference(uint64_t fromAddr, uint64_t toAddr);

		/*! Remove a user Data Reference from a virtual address to another virtual address

		    \param fromAddr Address referencing the toAddr value
		    \param toAddr virtual address being referenced
		*/
		void RemoveUserDataReference(uint64_t fromAddr, uint64_t toAddr);

		// References to type

		/*! Get code references to a Type

		    \param type QualifiedName for a Type
		    \return vector of ReferenceSources
		*/
		std::vector<ReferenceSource> GetCodeReferencesForType(const QualifiedName& type);

		/*! Get data references to a Type

		    \param type QualifiedName for a Type
		    \return vector of virtual addresses referencing this Type
		*/
		std::vector<uint64_t> GetDataReferencesForType(const QualifiedName& type);

		/*! Get Type references to a Type

		    \param type QualifiedName for a Type
		    \return vector of TypeReferenceSources to this Type
		*/
		std::vector<TypeReferenceSource> GetTypeReferencesForType(const QualifiedName& type);

		/*! Returns a list of references to a specific type field

			\param type QualifiedName of the type
			\param offset Offset of the field, relative to the start of the type
			\return vector of TypeFieldReferences
		*/
		std::vector<TypeFieldReference> GetCodeReferencesForTypeField(const QualifiedName& type, uint64_t offset);

		/*! Returns a list of virtual addresses of data which references the type \c type .

			Note, the returned addresses are the actual start of the queried type field. For example, suppose there is a
			DataVariable at \c 0x1000 that has type \c A , and type \c A contains type \c B at offset \c 0x10 .
			Then <tt>GetDataReferencesForTypeField(bQualifiedName, 0x8)</tt> will return \c 0x1018 for it.

			\param type QualifiedName of the type
			\param offset Offset of the field, relative to the start of the type
			\return List of DataVariable start addresses containing references to the type field
		*/
		std::vector<uint64_t> GetDataReferencesForTypeField(const QualifiedName& type, uint64_t offset);

		/*! Returns a list of type references to a specific type field

			\param type QualifiedName of the type
			\param offset Offset of the field, relative to the start of the type
			\return vector of TypeReferenceSources
		*/
		std::vector<TypeReferenceSource> GetTypeReferencesForTypeField(const QualifiedName& type, uint64_t offset);

		/*! Returns a list of types referenced by code at ReferenceSource \c src

			If no function is specified, references from all functions and containing the address will be returned.
		 	If no architecture is specified, the architecture of the function will be used.

			\param src Source of the reference to check
		 	\return vector of TypeReferenceSources
		*/
		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFrom(ReferenceSource src);

		/*! Returns a list of types referenced by code at ReferenceSource \c src

			If no function is specified, references from all functions and containing the address will be returned.
		 	If no architecture is specified, the architecture of the function will be used.

			\param src Source location to check
			\param len Length of the query
			\return vector of TypeReferenceSources
		*/
		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFrom(ReferenceSource src, uint64_t len);

		/*! Returns a list of type fields referenced by code at ReferenceSource \c src

			If no function is specified, references from all functions and containing the address will be returned.
		 	If no architecture is specified, the architecture of the function will be used.

			\param src Source location to check
			\return vector of TypeReferenceSources
		*/
		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFieldFrom(ReferenceSource src);

		/*! Returns a list of type fields referenced by code at ReferenceSource \c src

			If no function is specified, references from all functions and containing the address will be returned.
		 	If no architecture is specified, the architecture of the function will be used.

			\param src Source location to check
			\param len Length of the query
			\return vector of TypeReferenceSources
		*/
		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFieldFrom(ReferenceSource src, uint64_t len);

		/*! Returns a list of offsets in the QualifiedName specified by name, which are referenced by code.

			\param type Name of type to query for references
			\return List of offsets
		*/
		std::vector<uint64_t> GetAllFieldsReferenced(const QualifiedName& type);

		/*! Returns a map from field offset to a list of sizes of the accesses to the specified type.

			\param type Name of type to query for references
			\return A map from field offset to the	size of the code accesses to it
		*/
		std::map<uint64_t, std::vector<size_t>> GetAllSizesReferenced(const QualifiedName& type);

		/*! Returns a map from field offset to a list of incoming types written to the specified type.

			\param type Name of type to query for references
			\return A map from field offset to a list of incoming types written to it
		*/
		std::map<uint64_t, std::vector<Confidence<Ref<Type>>>> GetAllTypesReferenced(const QualifiedName& type);

		/*! Returns a list of types related to the type field access.

			\param type Name of type to query for references
			\param offset Offset of the field, relative to the start of the type
			\return A list of sizes of accesses to the type
		*/
		std::vector<size_t> GetSizesReferenced(const QualifiedName& type, uint64_t offset);

		/*! Returns a list of types referenced by a particular type field

			\param type Name of type to query for references
			\param offset Offset of the field, relative to the start of the type
			\return A list of types referenced
		*/
		std::vector<Confidence<Ref<Type>>> GetTypesReferenced(const QualifiedName& type, uint64_t offset);

		Ref<Structure> CreateStructureBasedOnFieldAccesses(const QualifiedName& type); // Unimplemented!

		/*! Returns a list of virtual addresses called by the call site in the ReferenceSource

			If no function is specified, call sites from
			all functions and containing the address will be considered. If no architecture is specified, the
			architecture of the function will be used.

			\param addr ReferenceSource to get callees to
			\return A list of addresses referencing the ReferenceSource
		*/
		std::vector<uint64_t> GetCallees(ReferenceSource addr);

		/*! Returns a list of ReferenceSource objects (xrefs or cross-references) that call the provided virtual address

			In this case, tail calls, jumps, and ordinary calls are considered.

			\param addr Address to check callers for
			\return A list of ReferenceSources calling this address
		*/
		std::vector<ReferenceSource> GetCallers(uint64_t addr);

		/*! Returns the Symbol at the provided virtual address

			\param addr Virtual address to query for symbol
			\param nameSpace The optional namespace of the symbols to retrieve
			\return The symbol located at that address
		*/
		Ref<Symbol> GetSymbolByAddress(uint64_t addr, const NameSpace& nameSpace = NameSpace());

		/*! Retrieves a Symbol object for the given a raw (mangled) name.

			\param name Raw (mangled) name of the symbol
			\param nameSpace The optional namespace of the symbols to retrieve
			\return The symbol with that raw name
		*/
		Ref<Symbol> GetSymbolByRawName(const std::string& name, const NameSpace& nameSpace = NameSpace());

		/*! Retrieves a list of symbols with a given name

			\param name Name to search for
			\param nameSpace The optional namespace of the symbols to retrieve
			\return List of symbols with that name
		*/
		std::vector<Ref<Symbol>> GetSymbolsByName(const std::string& name, const NameSpace& nameSpace = NameSpace());

		/*! Retrieves the list of all Symbol objects

			\param nameSpace The optional namespace of the symbols to retrieve
			\return A list of symbols
		*/
		std::vector<Ref<Symbol>> GetSymbols(const NameSpace& nameSpace = NameSpace());

		/*! Retrieves a list of symbols in a given range

			\param start Virtual address start of the range
			\param len Length of the range
			\param nameSpace The optional namespace of the symbols to retrieve
			\return A list of symbols for a given type
		*/
		std::vector<Ref<Symbol>> GetSymbols(uint64_t start, uint64_t len, const NameSpace& nameSpace = NameSpace());

		/*! Retrieves a list of all Symbol objects of the provided symbol type

			\param type The symbol type
			\param nameSpace The optional namespace of the symbols to retrieve
			\return A list of symbols for a given type
		*/
		std::vector<Ref<Symbol>> GetSymbolsOfType(BNSymbolType type, const NameSpace& nameSpace = NameSpace());

		/*! Retrieves a list of all Symbol objects of the provided symbol type in the given range

			\param type The symbol type
			\param start Virtual address start of the range
			\param len Length of the range
			\param nameSpace The optional namespace of the symbols to retrieve
			\return A list of symbols for a given type in the given range
		*/
		std::vector<Ref<Symbol>> GetSymbolsOfType(
		    BNSymbolType type, uint64_t start, uint64_t len, const NameSpace& nameSpace = NameSpace());

		/*! Get the list of visible symbols

			\param nameSpace The optional namespace of the symbols to retrieve
			\return A list of visible symbols
		*/
		std::vector<Ref<Symbol>> GetVisibleSymbols(const NameSpace& nameSpace = NameSpace());

		/*! Adds a symbol to the internal list of automatically discovered Symbol objects in a given namespace

			\warning If multiple symbols for the same address are defined, only the most recent symbol will ever be used.

			\param sym Symbol to define
		*/
		void DefineAutoSymbol(Ref<Symbol> sym);

		/*! Defines an "Auto" symbol, and a Variable/Function alongside it

			\param platform Platform for the Type being defined
			\param sym Symbol being definedd
			\param type Type being defined
			\return The defined symbol
		*/
		Ref<Symbol> DefineAutoSymbolAndVariableOrFunction(Ref<Platform> platform, Ref<Symbol> sym, Ref<Type> type);

		/*! Undefine an automatically defined symbol

			\param sym The symbol to undefine
		*/
		void UndefineAutoSymbol(Ref<Symbol> sym);

		/*! Define a user symbol

			\param sym Symbol to define
		*/
		void DefineUserSymbol(Ref<Symbol> sym);

		/*! Undefine a user symbol

			\param sym Symbol to undefinee
		*/
		void UndefineUserSymbol(Ref<Symbol> sym);

		/*! Defines an imported Function \c func with a ImportedFunctionSymbol type

			\param importAddressSym Symbol for the imported function
			\param func Function to define as an imported function
			\param type Optional type for the function
		*/
		void DefineImportedFunction(Ref<Symbol> importAddressSym, Ref<Function> func, Ref<Type> type = nullptr);

		/*! The current debug info object for this binary view

			\return The current debug info object for this binary view
		*/
		Ref<DebugInfo> GetDebugInfo();

		/*! Sets the debug info and applies its contents to the current BinaryView

			\param newDebugInfo 
		*/
		void ApplyDebugInfo(Ref<DebugInfo> newDebugInfo);

		/*! Sets the debug info for the current binary view

			\param newDebugInfo Sets the debug info for the current binary view
		*/
		void SetDebugInfo(Ref<DebugInfo> newDebugInfo);

		void BeginBulkModifySymbols();
		void EndBulkModifySymbols();

		/*! Add a new TagType to this binaryview

			\param tagType TagType to add
		*/
		void AddTagType(Ref<TagType> tagType);

		/*! Remove a TagType from this binaryview

			\param tagType TagType to remove
		*/
		void RemoveTagType(Ref<TagType> tagType);

		/*! Get a TagType by name

			\param name Name of the TagType
			\return The TagType, if it was found
		*/
		Ref<TagType> GetTagType(const std::string& name);

		/*! Get a TagType by name and TagType::Type

			\param name Name of the TagType
			\param type Type of the TagType
			\return The TagType, if it was found
		*/
		Ref<TagType> GetTagType(const std::string& name, TagType::Type type);

		/*! Get a TagType by name

			\param name Name of the TagType
			\return The TagType, if it was found
		*/
		Ref<TagType> GetTagTypeByName(const std::string& name);

		/*! Get a TagType by name and TagType::Type

			\param name Name of the TagType
			\param type Type of the TagType
			\return The TagType, if it was found
		*/
		Ref<TagType> GetTagTypeByName(const std::string& name, TagType::Type type);

		/*! Get a TagType by its ID

			\param id ID of the TagType
			\return The TagType, if it was found
		*/
		Ref<TagType> GetTagTypeById(const std::string& id);

		/*! Get a TagType by its ID and TagType::Type

			\param id ID of the TagType
			\param type Type of the TagType
			\return The TagType, if it was found
		*/
		Ref<TagType> GetTagTypeById(const std::string& id, TagType::Type type);

		/*! Get the list of all defined TagTypes

			\return Get the list of all defined TagTypes
		*/
		std::vector<Ref<TagType>> GetTagTypes();

		/*! Add a Tag

			\param tag The tag to add
			\param user Whether this was added by a user or automatically by analysis
		*/
		void AddTag(Ref<Tag> tag, bool user = false);

		/*! Remove a tag

			\param tag The tag to remove
			\param user Whether the tag being removed is a user tag
		*/
		void RemoveTag(Ref<Tag> tag, bool user = false);

		/*! Get a tag by its ID

			\param tagId the tag ID
			\return The tag, if it was found
		*/
		Ref<Tag> GetTag(const std::string& tagId);

		std::vector<TagReference> GetAllTagReferences();
		std::vector<TagReference> GetAllAddressTagReferences();
		std::vector<TagReference> GetAllFunctionTagReferences();
		std::vector<TagReference> GetAllTagReferencesOfType(Ref<TagType> tagType);

		std::vector<TagReference> GetTagReferencesOfType(Ref<TagType> tagType);
		size_t GetTagReferencesOfTypeCount(Ref<TagType> tagType);
		size_t GetAllTagReferencesOfTypeCount(Ref<TagType> tagType);
		std::map<Ref<TagType>, size_t> GetAllTagReferenceTypeCounts();

		std::vector<TagReference> GetDataTagReferences();
		std::vector<TagReference> GetAutoDataTagReferences();
		std::vector<TagReference> GetUserDataTagReferences();
		std::vector<Ref<Tag>> GetDataTags(uint64_t addr);
		std::vector<Ref<Tag>> GetAutoDataTags(uint64_t addr);
		std::vector<Ref<Tag>> GetUserDataTags(uint64_t addr);
		std::vector<Ref<Tag>> GetDataTagsOfType(uint64_t addr, Ref<TagType> tagType);
		std::vector<Ref<Tag>> GetAutoDataTagsOfType(uint64_t addr, Ref<TagType> tagType);
		std::vector<Ref<Tag>> GetUserDataTagsOfType(uint64_t addr, Ref<TagType> tagType);
		std::vector<TagReference> GetDataTagsInRange(uint64_t start, uint64_t end);
		std::vector<TagReference> GetAutoDataTagsInRange(uint64_t start, uint64_t end);
		std::vector<TagReference> GetUserDataTagsInRange(uint64_t start, uint64_t end);
		void AddAutoDataTag(uint64_t addr, Ref<Tag> tag);
		void RemoveAutoDataTag(uint64_t addr, Ref<Tag> tag);
		void RemoveAutoDataTagsOfType(uint64_t addr, Ref<TagType> tagType);
		void AddUserDataTag(uint64_t addr, Ref<Tag> tag);
		void RemoveUserDataTag(uint64_t addr, Ref<Tag> tag);
		void RemoveUserDataTagsOfType(uint64_t addr, Ref<TagType> tagType);
		void RemoveTagReference(const TagReference& ref);

		Ref<Tag> CreateAutoDataTag(
		    uint64_t addr, const std::string& tagTypeName, const std::string& data, bool unique = false);
		Ref<Tag> CreateUserDataTag(
		    uint64_t addr, const std::string& tagTypeName, const std::string& data, bool unique = false);

		Ref<Tag> CreateAutoDataTag(uint64_t addr, Ref<TagType> tagType, const std::string& data, bool unique = false);
		Ref<Tag> CreateUserDataTag(uint64_t addr, Ref<TagType> tagType, const std::string& data, bool unique = false);

		/*! Lookup a component by its GUID

			\param guid GUID of the component to look up
			\return The component with that GUID
		*/
		std::optional<Ref<Component>> GetComponentByGuid(std::string guid);

		/*! Lookup a component by its pathname

			\note This is a convenience method, and for performance-sensitive lookups, GetComponentByGuid is very
		 	highly recommended.

		 	\see GetComponentByGuid, Component::GetGuid

			All lookups are absolute from the root component, and are case-sensitive. Pathnames are delimited with "/"

		 	Lookups are done using the display name of the component, which is liable to change when it or its siblings
		 	are moved around.

		 	\see Component::GetDisplayName

			\param path Path of the desired component
			\return The component at that path
		*/
		std::optional<Ref<Component>> GetComponentByPath(std::string path);

		/*! Get the root component for the BinaryView (read-only)

			This Component cannot be removed, and houses all unparented Components.

			\return The Root Component
		*/
		Ref<Component> GetRootComponent();

		/*! Create a component

			This component will be added to the root component and initialized with the name "Component"

			\return The created Component
		*/
		Ref<Component> CreateComponent();

		/*! Create a component as a subcomponent of the component with a given Guid

			This component will be initialized with the name "Component"

			\param parentGUID Guid of the component this component will be added to
			\return The created Component
		*/
		Ref<Component> CreateComponent(std::string parentGUID);

		/*! Create a component as a subcomponent of a given Component

		    This component will be initialized with the name "Component"

		 	\param parent Parent Component
		 	\return The created Component
		*/
		Ref<Component> CreateComponent(Ref<Component> parent);

		/*! Create a component with a given name and optional parent

		    \param name Name to initialize the component with
		    \param parentGUID Optional Guid of the component this component will be added to
		    \return The created Component
		*/
		Ref<Component> CreateComponentWithName(std::string name, std::string parentGUID = {});

		/*! Create a component with a given name and parent

		    \param name Name to initialize the component with
		    \param parentGUID Guid of the component this component will be added to
		    \return The created Component
		*/
		Ref<Component> CreateComponentWithName(std::string name, Ref<Component> parent);

		/*! Remove a component from the tree entirely. This will also by nature remove all subcomponents.

			\param component Component to remove
			\return Whether removal was successful
		*/
		bool RemoveComponent(Ref<Component> component);

		/*! Remove a component from the tree entirely. This will also by nature remove all subcomponents.

			\param guid Guid of the Component to remove
			\return Whether removal was successful
		*/
		bool RemoveComponent(std::string guid);

		/*! Check whether the given architecture supports assembling instructions

			\param arch Architecture to check
			\return Whether the given architecture supports assembling instructions
		*/
		bool CanAssemble(Architecture* arch);

		/*! Check whether the "Never Branch" patch is available for a given architecture at a given address

			\param arch Architecture to check
			\param addr Address of the instruction to be patched
			\return Whether the "Never Branch" patch is available
		*/
		bool IsNeverBranchPatchAvailable(Architecture* arch, uint64_t addr);

		/*! Check whether the "Always Branch" patch is available for a given architecture at a given address

			\param arch Architecture to check
			\param addr Address of the instruction to be patched
			\return Whether the "Always Branch" patch is available
		*/
		bool IsAlwaysBranchPatchAvailable(Architecture* arch, uint64_t addr);

		/*! Check whether the "Invert Branch" patch is available for a given architecture at a given address

			\param arch Architecture to check
			\param addr Address of the instruction to be patched
			\return Whether the "Invert Branch" patch is available
		*/
		bool IsInvertBranchPatchAvailable(Architecture* arch, uint64_t addr);

		/*! Check whether the "Skip and Return Zero" patch is available for a given architecture at a given address

			\param arch Architecture to check
			\param addr Address of the instruction to be patched
			\return Whether the "Skip and Return Zero" patch is available
		*/
		bool IsSkipAndReturnZeroPatchAvailable(Architecture* arch, uint64_t addr);

		/*! Check whether the "Skip and Return Value" patch is available for a given architecture at a given address

			\param arch Architecture to check
			\param addr Address of the instruction to be patched
			\return Whether the "Skip and Return Value" patch is available
		*/
		bool IsSkipAndReturnValuePatchAvailable(Architecture* arch, uint64_t addr);

		/*! Convert the instruction at the given address to a nop

			\param arch Architecture of the instruction to convert
			\param addr Address of the instruction to be patched
			\return Whether the patch was successful
		*/
		bool ConvertToNop(Architecture* arch, uint64_t addr);

		/*! Convert the conditional branch at the given address to always branch

			\param arch Architecture of the instruction to convert
			\param addr Address of the instruction to be patched
			\return Whether the patch was successful
		*/
		bool AlwaysBranch(Architecture* arch, uint64_t addr);

		/*! Convert the conditional branch at the given address to branch under inverted conditions

			\param arch Architecture of the instruction to convert
			\param addr Address of the instruction to be patched
			\return Whether the patch was successful
		*/
		bool InvertBranch(Architecture* arch, uint64_t addr);

		/*! Convert the given instruction to skip the rest of the function and return 0

			\param arch Architecture of the instruction to convert
			\param addr Address of the instruction to be patched
			\param value Value to return
			\return Whether the patch was successful
		*/
		bool SkipAndReturnValue(Architecture* arch, uint64_t addr, uint64_t value);

		/*! Get the length of the instruction at a given address

			\param arch Architecture of the instruction
			\param addr Address of the start of the instruction
			\return The length of the instruction
		*/
		size_t GetInstructionLength(Architecture* arch, uint64_t addr);

		/*! Get the string at an address

			\param[in] addr Address of the string
			\param[out] strRef Reference to a StringReference the string reference will be writen to.
			\return Whether a string was at th given address
		*/
		bool GetStringAtAddress(uint64_t addr, BNStringReference& strRef);

		/*! Get the list of strings located within the view

			\return The list of strings
		*/
		std::vector<BNStringReference> GetStrings();

		/*! Get the list of strings located within a range

			\param start Starting virtual address of the range
			\param len Length of the range
			\return The list of strings
		*/
		std::vector<BNStringReference> GetStrings(uint64_t start, uint64_t len);

		/*! Sets up a call back function to be called when analysis has been completed.

			This is helpful when using `UpdateAnalysis` which does not wait for analysis completion before returning.

			The callee of this function is not responsible for maintaining the lifetime of the returned AnalysisCompletionEvent object

			\param callback A function to be called with no parameters when analysis has completed.
			\return An initialized AnalysisCompletionEvent object.
		*/
		Ref<AnalysisCompletionEvent> AddAnalysisCompletionEvent(const std::function<void()>& callback);

		AnalysisInfo GetAnalysisInfo();
		BNAnalysisProgress GetAnalysisProgress();
		Ref<BackgroundTask> GetBackgroundAnalysisTask();

		/*! Returns the virtual address of the Function that occurs after the virtual address `addr`

			\param addr Address to start searching
			\return Next function start
		*/
		uint64_t GetNextFunctionStartAfterAddress(uint64_t addr);

		/*! Returns the virtual address of the BasicBlock that occurs after the virtual address `addr`

			\param addr Address to start searching
			\return Next basic block start
		*/
		uint64_t GetNextBasicBlockStartAfterAddress(uint64_t addr);

		/*! Retrieves the virtual address of the next non-code byte.

			\param addr Address to start searching
			\return address of the next non-code byte
		*/
		uint64_t GetNextDataAfterAddress(uint64_t addr);

		/*! Retrieves the address of the next DataVariable.

			\param addr Address to start searching
			\return address of the next DataVariable
		*/
		uint64_t GetNextDataVariableStartAfterAddress(uint64_t addr);

		/*! Returns the virtual address of the Function that occurs prior to the
			virtual address provided

			\param addr Address to start searching
			\return the virtual address of the previous Function
		*/
		uint64_t GetPreviousFunctionStartBeforeAddress(uint64_t addr);

		/*! Returns the virtual address of the Basic Block that occurs prior to the
			virtual address provided

			\param addr Address to start searching
			\return The virtual address of the previous Basic Block
		*/
		uint64_t GetPreviousBasicBlockStartBeforeAddress(uint64_t addr);

		/*! Returns the ending virtual address of the Basic Block that occurs prior to the
			virtual address provided

			\param addr Address to start searching
			\return The ending virtual address of the previous Basic Block
		*/
		uint64_t GetPreviousBasicBlockEndBeforeAddress(uint64_t addr);

		/*! Returns the virtual address of the previous data (non-code) byte

			\param addr Address to start searching
			\return The virtual address of the previous non-code byte
		*/
		uint64_t GetPreviousDataBeforeAddress(uint64_t addr);

		/*! Returns the virtual address of the previous DataVariable

			\param addr Address to start searching
			\return The virtual address of the previous DataVariable
		*/
		uint64_t GetPreviousDataVariableStartBeforeAddress(uint64_t addr);

		bool ParsePossibleValueSet(const std::string& value, BNRegisterValueType state, PossibleValueSet& result,
		    uint64_t here, std::string& errors);

		/*! Parse a single type and name from a string containing their definition

			\param[in] text Text containing the type definition
			\param[out] result Reference into which the resulting type and name will be written
			\param[out] errors Reference to a list into which any parse errors will be written
			\param typesAllowRedefinition
			\return Whether parsing was successful
		*/
		bool ParseTypeString(const std::string& text, QualifiedNameAndType& result, std::string& errors,
		    const std::set<QualifiedName>& typesAllowRedefinition = {});

		/*! Parse an entire block of source into types, variables, and functions

			\param[in] text Source code to parse
			\param[out] types Reference to a map of QualifiedNames and Types the parsed types will be writen to
			\param[out] variables Reference to a list of QualifiedNames and Types the parsed variables will be writen to
			\param[out] functions Reference to a list of QualifiedNames and Types the parsed functions will be writen to
			\param[out] errors Reference to a list into which any parse errors will be written
			\param typesAllowRedefinition
			\return Whether parsing was successful
		*/
		bool ParseTypeString(const std::string& text, std::map<QualifiedName, Ref<Type>>& types,
		    std::map<QualifiedName, Ref<Type>>& variables, std::map<QualifiedName, Ref<Type>>& functions,
		    std::string& errors, const std::set<QualifiedName>& typesAllowRedefinition = {});
		bool ParseTypesFromSource(const std::string& text, const std::vector<std::string>& options, const std::vector<std::string>& includeDirs, TypeParserResult& result,
		    std::string& errors, const std::set<QualifiedName>& typesAllowRedefinition = {});

		std::map<QualifiedName, Ref<Type>> GetTypes();
		std::vector<QualifiedName> GetTypeNames(const std::string& matching = "");
		Ref<Type> GetTypeByName(const QualifiedName& name);
		Ref<Type> GetTypeByRef(Ref<NamedTypeReference> name);
		Ref<Type> GetTypeById(const std::string& id);
		std::string GetTypeId(const QualifiedName& name);
		QualifiedName GetTypeNameById(const std::string& id);
		bool IsTypeAutoDefined(const QualifiedName& name);
		QualifiedName DefineType(const std::string& id, const QualifiedName& defaultName, Ref<Type> type);
		void DefineTypes(const std::vector<std::pair<std::string, QualifiedNameAndType>>& types, std::function<bool(size_t, size_t)> progress = {});
		void DefineUserType(const QualifiedName& name, Ref<Type> type);
		void DefineUserTypes(const std::vector<QualifiedNameAndType>& types, std::function<bool(size_t, size_t)> progress = {});
		void UndefineType(const std::string& id);
		void UndefineUserType(const QualifiedName& name);
		void RenameType(const QualifiedName& oldName, const QualifiedName& newName);

		void RegisterPlatformTypes(Platform* platform);

		bool FindNextData(
		    uint64_t start, const DataBuffer& data, uint64_t& result, BNFindFlag flags = FindCaseSensitive);
		bool FindNextText(uint64_t start, const std::string& data, uint64_t& result, Ref<DisassemblySettings> settings,
		    BNFindFlag flags = FindCaseSensitive, BNFunctionGraphType graph = NormalFunctionGraph);
		bool FindNextConstant(uint64_t start, uint64_t constant, uint64_t& result, Ref<DisassemblySettings> settings,
		    BNFunctionGraphType graph = NormalFunctionGraph);

		bool FindNextData(uint64_t start, uint64_t end, const DataBuffer& data, uint64_t& addr, BNFindFlag flags,
		    const std::function<bool(size_t current, size_t total)>& progress);
		bool FindNextText(uint64_t start, uint64_t end, const std::string& data, uint64_t& addr,
		    Ref<DisassemblySettings> settings, BNFindFlag flags, BNFunctionGraphType graph,
		    const std::function<bool(size_t current, size_t total)>& progress);
		bool FindNextConstant(uint64_t start, uint64_t end, uint64_t constant, uint64_t& addr,
		    Ref<DisassemblySettings> settings, BNFunctionGraphType graph,
		    const std::function<bool(size_t current, size_t total)>& progress);

		bool FindAllData(uint64_t start, uint64_t end, const DataBuffer& data, BNFindFlag flags,
		    const std::function<bool(size_t current, size_t total)>& progress,
		    const std::function<bool(uint64_t addr, const DataBuffer& match)>& matchCallback);
		bool FindAllText(uint64_t start, uint64_t end, const std::string& data, Ref<DisassemblySettings> settings,
		    BNFindFlag flags, BNFunctionGraphType graph,
		    const std::function<bool(size_t current, size_t total)>& progress,
		    const std::function<bool(uint64_t addr, const std::string& match, const LinearDisassemblyLine& line)>&
		        matchCallback);
		bool FindAllConstant(uint64_t start, uint64_t end, uint64_t constant, Ref<DisassemblySettings> settings,
		    BNFunctionGraphType graph, const std::function<bool(size_t current, size_t total)>& progress,
		    const std::function<bool(uint64_t addr, const LinearDisassemblyLine& line)>& matchCallback);

		void Reanalyze();

		Ref<Workflow> GetWorkflow() const;

		/*! Displays contents to the user in the UI or on the command-line

			\note This API functions differently on the command-line vs the UI. In the UI, it will be rendered in a new tab. From
			the command line, a simple text prompt is used.

			\param title Title for the report
			\param contents Contents of the report
		*/
		void ShowPlainTextReport(const std::string& title, const std::string& contents);

		/*! Displays markdown contents to the user in the UI or on the command-line

			\note This API functions differently on the command-line vs the UI. In the UI, it will be rendered in a new tab. From
			the command line, a simple text prompt is used.

			\param title Title for the report
			\param contents Markdown contents of the report
			\param plainText Plaintext contents of the report (used on the command line)
		*/
		void ShowMarkdownReport(const std::string& title, const std::string& contents, const std::string& plainText);

		/*! Displays HTML contents to the user in the UI or on the command-line

			\note This API functions differently on the command-line vs the UI. In the UI, it will be rendered in a new tab. From
			the command line, a simple text prompt is used.

			\param title Title for the report
			\param contents HTML contents of the report
			\param plainText Plaintext contents of the report (used on the command line)
		*/
		void ShowHTMLReport(const std::string& title, const std::string& contents, const std::string& plainText);

		/*! Displays a flow graph in UI applications and nothing in command-line applications.

			\note This API has no effect outside of the UI

			\param title Title for the report
			\param graph FlowGraph object to be rendered.
		*/
		void ShowGraphReport(const std::string& title, FlowGraph* graph);

		/*! Prompts the user to input an unsigned integer with the given prompt and title

			\param[out] result Reference to the uint64_t the result will be copied to
			\param[in] prompt Prompt for the input
			\param[in] title Title for the input popup when used in UI
			\return Whether an integer was successfully received
		*/
		bool GetAddressInput(uint64_t& result, const std::string& prompt, const std::string& title);

		/*! Prompts the user to input an unsigned integer with the given prompt and title

			\param[out] result Reference to the uint64_t the result will be copied to
			\param[in] prompt Prompt for the input
			\param[in] title Title for the input popup when used in UI
		 	\param[in] currentAddress Address to use for relative inputs
			\return Whether an integer was successfully received
		*/
		bool GetAddressInput(
		    uint64_t& result, const std::string& prompt, const std::string& title, uint64_t currentAddress);

		/*! Add an analysis segment that specifies how data from the raw file is mapped into a virtual address space

			\param start Starting virtual address
			\param length Length within the virtual address space
			\param dataOffset Data offset in the raw file
			\param dataLength Length of the data to map from the raw file
			\param flags Segment r/w/x flags
		*/
		void AddAutoSegment(uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags);

		/*! Removes an automatically generated segment from the current segment mapping

			\warning This action is not persistent across saving of a BNDB and must be re-applied each time a BNDB is loaded.

			\param start Virtual address of the start of the segment
			\param length Length of the segment
		*/
		void RemoveAutoSegment(uint64_t start, uint64_t length);

		/*! Creates a user-defined segment that specifies how data from the raw file is mapped into a virtual address space

			\param start Starting virtual address
			\param length Length within the virtual address space
			\param dataOffset Data offset in the raw file
			\param dataLength Length of the data to map from the raw file
			\param flags Segment r/w/x flags
		*/
		void AddUserSegment(uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags);

		/*! Removes a user-defined segment from th current segment mapping

			\param start Virtual address of the start of the segment
			\param length Length of the segment
		*/
		void RemoveUserSegment(uint64_t start, uint64_t length);

		/*! Get the list of registered Segments

			\return The list of registered Segments
		*/
		std::vector<Ref<Segment>> GetSegments();

		/*! Gets the Segment a given virtual address is located in

			\param addr A virtual address
			\return The Segment that virtual address is located im
		*/
		Ref<Segment> GetSegmentAt(uint64_t addr);

		/*! Retrieves the virtual addreses that maps to the given file offset, if possible.

			\param[in] offset Raw file offset
			\param[out] addr Reference to a uint64_t the address will be written to
			\return Whether an address was successfully mapped
		*/
		bool GetAddressForDataOffset(uint64_t offset, uint64_t& addr);

		/*! Creates an analysis-defined section that can help inform analysis by clarifying what types of data exist in
			what ranges

		 	Note that all data specified must already be mapped by an existing segment.

			\param name Name of the section
			\param start Virtual address of the start of the section
			\param length Length of the section
			\param semantics SectionSemantics of the section
			\param type Optional type of the section
			\param align Optional byte alignment
			\param entrySize Entry Size of the section
			\param linkedSection Optional namee of a linked section
			\param infoSection Optional name of an associated informational section
			\param infoData Optional Info Data
		*/
		void AddAutoSection(const std::string& name, uint64_t start, uint64_t length,
		    BNSectionSemantics semantics = DefaultSectionSemantics, const std::string& type = "", uint64_t align = 1,
		    uint64_t entrySize = 0, const std::string& linkedSection = "", const std::string& infoSection = "",
		    uint64_t infoData = 0);

		/*! Remove an automatically defined section by name

			\param name Name of the section
		*/
		void RemoveAutoSection(const std::string& name);

		/*! Creates a user-defined section that can help inform analysis by clarifying what types of data exist in
			what ranges

		 	Note that all data specified must already be mapped by an existing segment.

			\param name Name of the section
			\param start Virtual address of the start of the section
			\param length Length of the section
			\param semantics SectionSemantics of the section
			\param type Optional type of the section
			\param align Optional byte alignment
			\param entrySize Entry Size of the section
			\param linkedSection Optional namee of a linked section
			\param infoSection Optional name of an associated informational section
			\param infoData Optional Info Data
		*/
		void AddUserSection(const std::string& name, uint64_t start, uint64_t length,
		    BNSectionSemantics semantics = DefaultSectionSemantics, const std::string& type = "", uint64_t align = 1,
		    uint64_t entrySize = 0, const std::string& linkedSection = "", const std::string& infoSection = "",
		    uint64_t infoData = 0);

		/*! Remove a user defined section by name

			\param name Name of the section to remove
		*/
		void RemoveUserSection(const std::string& name);

		/*! Get the list of defined sections

			\return The list of defined sections
		*/
		std::vector<Ref<Section>> GetSections();

		/*! Get the list of sections containing \c addr

			\param addr Address to check
			\return List of sections containing \c addr
		*/
		std::vector<Ref<Section>> GetSectionsAt(uint64_t addr);

		/*! Get a Section by name

			\param name Name of the Section
			\return The Section with that name
		*/
		Ref<Section> GetSectionByName(const std::string& name);

		/*! Create unique names for all items in the input list, modifying them if they are not unique

			\code{.cpp}
		    std::vector<std::string> names = bv.GetUniqueSectionNames({"sect1", "sect1", "sect2"});
			// names == {'sect1', 'sect1#1', 'sect2'}
		 	\endcode

			\param names List of names
			\return List of unique names
		*/
		std::vector<std::string> GetUniqueSectionNames(const std::vector<std::string>& names);

		/*! Get the comment placed at an address

			\param addr Address at which to check for a comment
			\return Comment at that address
		*/
		std::string GetCommentForAddress(uint64_t addr) const;

		/*! Get the list of commented addresses

			\return list of addresses with comments defined at them
		*/
		std::vector<uint64_t> GetCommentedAddresses() const;

		/*! Set the comment at an address

			\param addr Address at which to place a comment
			\param comment Comment to place
		*/
		void SetCommentForAddress(uint64_t addr, const std::string& comment);

		/*! Get the list of allocated ranges

			\return The list of allocated ranges
		*/
		std::vector<BNAddressRange> GetAllocatedRanges();

		void StoreMetadata(const std::string& key, Ref<Metadata> value, bool isAuto = false);
		Ref<Metadata> QueryMetadata(const std::string& key);
		void RemoveMetadata(const std::string& key);
		std::string GetStringMetadata(const std::string& key);
		std::vector<uint8_t> GetRawMetadata(const std::string& key);
		uint64_t GetUIntMetadata(const std::string& key);

		std::vector<std::string> GetLoadSettingsTypeNames();
		Ref<Settings> GetLoadSettings(const std::string& typeName);
		void SetLoadSettings(const std::string& typeName, Ref<Settings> settings);

		BNAnalysisParameters GetParametersForAnalysis();
		void SetParametersForAnalysis(BNAnalysisParameters params);
		uint64_t GetMaxFunctionSizeForAnalysis();
		void SetMaxFunctionSizeForAnalysis(uint64_t size);
		bool GetNewAutoFunctionAnalysisSuppressed();
		void SetNewAutoFunctionAnalysisSuppressed(bool suppress);

		/*! Returns a list of namespaces for the current BinaryView

			\return A list of namespaces for the current BinaryView
		*/
		std::set<NameSpace> GetNameSpaces() const;

		/*! Internal namespace for the current BinaryView

			\return Internal namespace for the current BinaryView
		*/
		static NameSpace GetInternalNameSpace();

		/*! External namespace for the current BinaryView

			\return External namespace for the current BinaryView
		*/
		static NameSpace GetExternalNameSpace();

		/*! Evaluates a string expression to an integer value.

			The parser uses the following rules:

			- Symbols are defined by the lexer as ``[A-Za-z0-9_:<>][A-Za-z0-9_:$\-<>]+`` or anything enclosed in either single or double quotes
			- Symbols are everything in ``bv.GetSymbols()``, unnamed DataVariables (i.e. ``data_00005000``), unnamed functions (i.e. ``sub_00005000``), or section names (i.e. ``.text``)
			- Numbers are defaulted to hexadecimal thus `_printf + 10` is equivalent to `printf + 0x10` If decimal numbers required use the decimal prefix.
			- Since numbers and symbols can be ambiguous its recommended that you prefix your numbers with the following:

					- ``0x`` - Hexadecimal
					- ``0n`` - Decimal
					- ``0`` - Octal

			- In the case of an ambiguous number/symbol (one with no prefix) for instance ``12345`` we will first attempt
			  to look up the string as a symbol, if a symbol is found its address is used, otherwise we attempt to convert
			  it to a hexadecimal number.
			- The following operations are valid: ``+, -, \*, /, %, (), &, \|, ^, ~``
			- In addition to the above operators there are dereference operators similar to BNIL style IL:

					- ``[<expression>]`` - read the `current address size` at ``<expression>``
					- ``[<expression>].b`` - read the byte at ``<expression>``
					- ``[<expression>].w`` - read the word (2 bytes) at ``<expression>``
					- ``[<expression>].d`` - read the dword (4 bytes) at ``<expression>``
					- ``[<expression>].q`` - read the quadword (8 bytes) at ``<expression>``

			- The ``$here`` (or more succinctly: ``$``) keyword can be used in calculations and is defined as the ``here`` parameter, or the currently selected address
			- The ``$start``/``$end`` keyword represents the address of the first/last bytes in the file respectively


			\param[in] view View object for relative selections
			\param[in] expression Expression to parse
			\param[out] offset Parsed expression
			\param[in] here The location for $here
			\param[out] errorString Any errors that occurred during parsing
			\return Whether the parsing was successful
		*/
		static bool ParseExpression(Ref<BinaryView> view, const std::string& expression, uint64_t& offset,
		    uint64_t here, std::string& errorString);

		/*! Check whether this BinaryView has any defined symbols

			\return Whether this BinaryView has any defined symbols
		*/
		bool HasSymbols() const;

		/*! Check whether this BinaryView has any defined DataVariables

			\return Whether this BinaryView has any defined DataVariables
		*/
		bool HasDataVariables() const;

		Ref<Structure> CreateStructureFromOffsetAccess(const QualifiedName& type, bool* newMemberAdded) const;
		Confidence<Ref<Type>> CreateStructureMemberFromAccess(const QualifiedName& name, uint64_t offset) const;

		/*! Create a logger with a session ID tied to this BinaryView.

		 	Whenever this logger is used, if "Log Scope" is set to "Current Tab", it will only be shown for tabs
		 	Displaying this BinaryView

		 	\see Logger
		 	\see LogRegistry

			\param name Name for the logger
			\return The created Logger
		*/
		Ref<Logger> CreateLogger(const std::string& name);
	};


	/*!
		\ingroup binaryview
	*/
	class Relocation : public CoreRefCountObject<BNRelocation, BNNewRelocationReference, BNFreeRelocation>
	{
	  public:
		Relocation(BNRelocation* reloc);
		BNRelocationInfo GetInfo() const;
		Architecture* GetArchitecture() const;
		uint64_t GetTarget() const;
		uint64_t GetAddress() const;
		Ref<Symbol> GetSymbol() const;
	};


	/*!
		\ingroup binaryview
	*/
	class BinaryData : public BinaryView
	{
	  public:
		BinaryData(FileMetadata* file);
		BinaryData(FileMetadata* file, const DataBuffer& data);
		BinaryData(FileMetadata* file, const void* data, size_t len);
		BinaryData(FileMetadata* file, const std::string& path);
		BinaryData(FileMetadata* file, FileAccessor* accessor);
	};

	class Platform;

	/*! The \c BinaryViewType object is used internally and should not be directly instantiated.
		\ingroup binaryview
	*/
	class BinaryViewType : public StaticCoreRefCountObject<BNBinaryViewType>
	{
		struct BinaryViewEvent
		{
			std::function<void(BinaryView*)> action;
		};

		struct PlatformRecognizerFunction
		{
			std::function<Ref<Platform>(BinaryView*, Metadata*)> action;
		};

	  protected:
		std::string m_nameForRegister, m_longNameForRegister;

		static BNBinaryView* CreateCallback(void* ctxt, BNBinaryView* data);
		static BNBinaryView* ParseCallback(void* ctxt, BNBinaryView* data);
		static bool IsValidCallback(void* ctxt, BNBinaryView* data);
		static bool IsDeprecatedCallback(void* ctxt);
		static BNSettings* GetSettingsCallback(void* ctxt, BNBinaryView* data);

		BinaryViewType(BNBinaryViewType* type);

	  public:
		BinaryViewType(const std::string& name, const std::string& longName);
		virtual ~BinaryViewType() {}

		/*! Register a BinaryViewType

			\param type BinaryViewType to register
		*/
		static void Register(BinaryViewType* type);

		/*! Get a BinaryViewType by name

			\param name Name of the registered BinaryViewType
			\return The BinaryViewType, if one was registered
		*/
		static Ref<BinaryViewType> GetByName(const std::string& name);

		/*! Get the list of registered View Types

			\return Get the list of registered View Types
		*/
		static std::vector<Ref<BinaryViewType>> GetViewTypes();

		/*! Get the list of valid view types for a BinaryView

			\param data BinaryView for a binary
			\return List of valid view types
		*/
		static std::vector<Ref<BinaryViewType>> GetViewTypesForData(BinaryView* data);

		/*! Register an Architecture for a specific view type

			\param name Name of the view type
			\param id ID of the architecture
			\param endian Endianness of the architecture
			\param arch Architecture
		*/
		static void RegisterArchitecture(const std::string& name, uint32_t id, BNEndianness endian, Architecture* arch);

		/*! Register an Architecture for this view type

			\param id ID of the architecture
			\param endian Endianness of the architecture
			\param arch Architecture
		*/
		void RegisterArchitecture(uint32_t id, BNEndianness endian, Architecture* arch);

		/*! Get an Architecture for this BinaryViewType by id and endianness

		    \param id ID of the architecture
		    \param endian Endianness of the architecture
			\return The architecture, if it was found
		*/
		Ref<Architecture> GetArchitecture(uint32_t id, BNEndianness endian);

		/*! Register a Platform for a specific view type

			\param name Name of the BinaryViewType
			\param id ID of the platform
			\param arch Architecture to register this platform with
			\param platform The Platform to register
		*/
		static void RegisterPlatform(const std::string& name, uint32_t id, Architecture* arch, Platform* platform);

		/*! Register a Platform as a default for a specific view type

			\param name Name of the BinaryViewType
			\param arch Architecture to register this platform with
			\param platform The Platform to register
		*/
		static void RegisterDefaultPlatform(const std::string& name, Architecture* arch, Platform* platform);

		/*! Register a Platform for this view type

			\param id ID of the platform
			\param arch Architecture to register this platform with
			\param platform The Platform to register
		*/
		void RegisterPlatform(uint32_t id, Architecture* arch, Platform* platform);

		/*! Register a Platform as a default for this view type

			\param arch Architecture to register this platform with
			\param platform The Platform to register
		*/
		void RegisterDefaultPlatform(Architecture* arch, Platform* platform);

		/*! Get a platform by ID and architecture

			\param id ID of the platform
			\param arch Architecture of the Platform
			\return The Platform, if it was found.
		*/
		Ref<Platform> GetPlatform(uint32_t id, Architecture* arch);

		void RegisterPlatformRecognizer(uint64_t id, BNEndianness endian,
		    const std::function<Ref<Platform>(BinaryView* view, Metadata*)>& callback);
		Ref<Platform> RecognizePlatform(uint64_t id, BNEndianness endian, BinaryView* view, Metadata* metadata);

		/*! Get the name this platform was registered with

			\return The name of the platform
		*/
		std::string GetName();

		/*! Get the "Long Name" this platform was registered with

			\return The "Long Name" this platform was registered with
		*/
		std::string GetLongName();

		virtual bool IsDeprecated();

		/*! Create a BinaryView for this BinaryViewType given the data from an existing BinaryView

			\param data An existing BinaryView, typically with the \c Raw type
			\return The BinaryView created by this BinaryViewType
		*/
		virtual BinaryView* Create(BinaryView* data) = 0;

		/*! Create ephemeral BinaryView to generate information for preview

			\param data An existing BinaryView, typically with the \c Raw type
			\return The BinaryView created by this BinaryViewType
		*/
		virtual BinaryView* Parse(BinaryView* data) = 0;

		/*! Check whether this BinaryViewType is valid for given data

			\param data An existing BinaryView, typically with the \c Raw type
			\return Whether this BinaryViewType is valid for given data
		*/
		virtual bool IsTypeValidForData(BinaryView* data) = 0;
		virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) = 0;

		static void RegisterBinaryViewFinalizationEvent(const std::function<void(BinaryView* view)>& callback);
		static void RegisterBinaryViewInitialAnalysisCompletionEvent(
		    const std::function<void(BinaryView* view)>& callback);

		static void BinaryViewEventCallback(void* ctxt, BNBinaryView* view);
		static BNPlatform* PlatformRecognizerCallback(void* ctxt, BNBinaryView* view, BNMetadata* metadata);
	};

	/*!
		\ingroup binaryview
	*/
	class CoreBinaryViewType : public BinaryViewType
	{
	  public:
		CoreBinaryViewType(BNBinaryViewType* type);
		virtual BinaryView* Create(BinaryView* data) override;
		virtual BinaryView* Parse(BinaryView* data) override;
		virtual bool IsTypeValidForData(BinaryView* data) override;
		virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override;
	};

	/*! Thrown whenever a read is performed out of bounds.

		\ingroup binaryview
	*/
	class ReadException : public std::exception
	{
	  public:
		ReadException() : std::exception() {}
		virtual const char* what() const NOEXCEPT { return "read out of bounds"; }
	};

	/*! BinaryReader is a convenience class for reading binary data
		\ingroup binaryview
	*/
	class BinaryReader
	{
		Ref<BinaryView> m_view;
		BNBinaryReader* m_stream;

	  public:
		/*! Create a BinaryReader instance given a BinaryView and endianness.

			\param data BinaryView to read from
			\param endian Byte order to read with. One of LittleEndian, BigEndian
		*/
		BinaryReader(BinaryView* data, BNEndianness endian = LittleEndian);
		~BinaryReader();

		/*! Get the endianness set for this reader.

			\return The endianness set for this reader.
		*/
		BNEndianness GetEndianness() const;

		/*! Set the endianness for this reader

		    \param endian Byte order to read with. One of LittleEndian, BigEndian
		*/
		void SetEndianness(BNEndianness endian);

		/*! Read from the current cursor position into buffer `dest`

		    \throws ReadException
			\param dest Address to write the read bytes to
			\param len Number of bytes to write
		*/
		void Read(void* dest, size_t len);
		/*! Read from the current cursor position into a DataBuffer

		    \throws ReadException
			\param len Number of bytes to read
			\return DataBuffer containing the bytes read
		*/
		DataBuffer Read(size_t len);
		template <typename T>
		T Read();
		template <typename T>
		std::vector<T> ReadVector(size_t count);

		/*! Read a string of fixed length from the current cursor position

		    \throws ReadException
			\param len Length of the string
			\return the string
		*/
		std::string ReadString(size_t len);

		/*! Read a null-terminated string from the current cursor position

		    \throws ReadException
			\param maxLength Maximum length of the string, default is no limit (-1)
			\return the string
		*/
		std::string ReadCString(size_t maxLength = -1);

		/*! Read a uint8_t from the current cursor position and advance the cursor by 1 byte

		    \throws ReadException
			\return The read value
		*/
		uint8_t Read8();

		/*! Read a uint16_t from the current cursor position and advance the cursor by 2 bytes

		    \throws ReadException
			\return The read value
		*/
		uint16_t Read16();

		/*! Read a uint32_t from the current cursor position and advance the cursor by 4 bytes

		    \throws ReadException
			\return The read value
		*/
		uint32_t Read32();

		/*! Read a uint64_t from the current cursor position and advance the cursor by 8 bytes

		    \throws ReadException
			\return The read value
		*/
		uint64_t Read64();

		/*! Read a uint16_t from the current cursor position, explicitly as a little endian value,
			and advance the cursor by 4 bytes

		    \throws ReadException
			\return The read value
		*/
		uint16_t ReadLE16();

		/*! Read a uint16_t from the current cursor position, explicitly as a little endian value,
			and advance the cursor by 4 bytes

		    \throws ReadException
			\return The read value
		*/
		uint32_t ReadLE32();

		/*! Read a uint16_t from the current cursor position, explicitly as a little endian value,
			and advance the cursor by 4 bytes

		    \throws ReadException
			\return The read value
		*/
		uint64_t ReadLE64();

		/*! Read a uint16_t from the current cursor position, explicitly as a big endian value,
			and advance the cursor by 4 bytes

		    \throws ReadException
			\return The read value
		*/
		uint16_t ReadBE16();

		/*! Read a uint16_t from the current cursor position, explicitly as a big endian value,
			and advance the cursor by 4 bytes

		    \throws ReadException
			\return The read value
		*/
		uint32_t ReadBE32();

		/*! Read a uint16_t from the current cursor position, explicitly as a big endian value,
			and advance the cursor by 4 bytes

		    \throws ReadException
			\return The read value
		*/
		uint64_t ReadBE64();

		/*! Try reading a value, returning false whenever that read fails

			\param dest Address to write the bytes to
			\param len Number of bytes to read
			\return Whether the read succeeded
		*/
		bool TryRead(void* dest, size_t len);

		/*! Try reading a value into a databuffer

			\param dest Reference to a DataBuffer to write to
			\param len Amount of bytes to read
			\return Whether the read succeeded
		*/
		bool TryRead(DataBuffer& dest, size_t len);

		/*! Try reading a string

			\param dest Reference to a string to write to
			\param len Length of the string to be read
			\return Whether the read succeeded
		*/
		bool TryReadString(std::string& dest, size_t len);

		/*! Try reading a uint8_t

			\param result Reference to a uint8_t to write to
			\return Whether the read succeeded.
		*/
		bool TryRead8(uint8_t& result);

		/*! Try reading a uint16_t

		    \param result Reference to a uint16_t to write to
		    \return Whether the read succeeded.
		*/
		bool TryRead16(uint16_t& result);

		/*! Try reading a uint32_t

			\param result Reference to a uint32_t to write to
			\return Whether the read succeeded.
		*/
		bool TryRead32(uint32_t& result);

		/*! Try reading a uint64_t

			\param result Reference to a uint64_t to write to
			\return Whether the read succeeded.
		*/
		bool TryRead64(uint64_t& result);

		/*! Try reading a uint16_t, explicitly as little endian

			\param result Reference to a uint16_t to write to
			\return Whether the read succeeded.
		*/
		bool TryReadLE16(uint16_t& result);

		/*! Try reading a uint32_t, explicitly as little endian

			\param result Reference to a uint32_t to write to
			\return Whether the read succeeded.
		*/
		bool TryReadLE32(uint32_t& result);

		/*! Try reading a uint64_t, explicitly as little endian

			\param result Reference to a uint64_t to write to
			\return Whether the read succeeded.
		*/
		bool TryReadLE64(uint64_t& result);

		/*! Try reading a uint16_t, explicitly as big endian

			\param result Reference to a uint16_t to write to
			\return Whether the read succeeded.
		*/
		bool TryReadBE16(uint16_t& result);

		/*! Try reading a uint32_t, explicitly as big endian

			\param result Reference to a uint32_t to write to
			\return Whether the read succeeded.
		*/
		bool TryReadBE32(uint32_t& result);

		/*! Try reading a uint64_t, explicitly as big endian

			\param result Reference to a uint64_t to write to
			\return Whether the read succeeded.
		*/
		bool TryReadBE64(uint64_t& result);

		/*! Get the current cursor position

			\return The current cursor position
		*/
		uint64_t GetOffset() const;

		/*! Set the cursor position

			\param offset The new cursor position
		*/
		void Seek(uint64_t offset);

		/*! Set the cursor position, relative to the current position

			\param offset Offset to the current cursor position
		*/
		void SeekRelative(int64_t offset);

		/*! Whether the current cursor position is at the end of the file.

		*/
		bool IsEndOfFile() const;
	};

	/*! Raised whenever a write is performed out of bounds.

		\ingroup binaryview
	*/
	class WriteException : public std::exception
	{
	  public:
		WriteException() : std::exception() {}
		virtual const char* what() const NOEXCEPT { return "write out of bounds"; }
	};

	/*! BinaryWriter is a convenience class for writing binary data
	 	\ingroup binaryview
	*/
	class BinaryWriter
	{
		Ref<BinaryView> m_view;
		BNBinaryWriter* m_stream;

	  public:

		/*! Create a BinaryWriter instance given a BinaryView and endianness.

			\param data BinaryView to write to
			\param endian Byte order to write with. One of LittleEndian, BigEndian
		*/
		BinaryWriter(BinaryView* data, BNEndianness endian = LittleEndian);
		~BinaryWriter();


		/*! Get the endianness set for this writer.

			\return The endianness set for this writer.
		*/
		BNEndianness GetEndianness() const;

		/*! Set the endianness for this writer

		    \param endian Byte order to write with. One of LittleEndian, BigEndian
		*/
		void SetEndianness(BNEndianness endian);

		/*! Write bytes from an address to the current cursor position

		 	\throws WriteException on out of bounds write
			\param src Address to read the bytes from
			\param len Amount of bytes to write
		*/
		void Write(const void* src, size_t len);

		/*! Write the contents of a DataBuffer to the current cursor position

		    \throws WriteException on out of bounds write
			\param buf DataBuffer to write from
		*/
		void Write(const DataBuffer& buf);

		/*! Write the contents of a string to the current cursor position

		    \throws WriteException on out of bounds write
			\param str String to write
		*/
		void Write(const std::string& str);

		/*! Write a uint8_t to the current cursor position

		    \throws WriteException on out of bounds write
			\param val uint8_t to write
		*/
		void Write8(uint8_t val);

		/*! Write a uint16_t to the current cursor position

		    \throws WriteException on out of bounds write
			\param val uint16_t to write
		*/
		void Write16(uint16_t val);

		/*! Write a uint32_t to the current cursor position

		    \throws WriteException on out of bounds write
			\param val uint32_t to write
		*/
		void Write32(uint32_t val);

		/*! Write a uint64_t to the current cursor position

		    \throws WriteException on out of bounds write
			\param val uint64_t to write
		*/
		void Write64(uint64_t val);

		/*! Write a uint16_t to the current cursor position, explicitly as little endian

		    \throws WriteException on out of bounds write
			\param val uint16_t to write
		*/
		void WriteLE16(uint16_t val);

		/*! Write a uint32_t to the current cursor position, explicitly as little endian

		    \throws WriteException on out of bounds write
			\param val uint32_t to write
		*/
		void WriteLE32(uint32_t val);

		/*! Write a uint64_t to the current cursor position, explicitly as little endian

		    \throws WriteException on out of bounds write
			\param val uint64_t to write
		*/
		void WriteLE64(uint64_t val);

		/*! Write a uint16_t to the current cursor position, explicitly as big endian

		    \throws WriteException on out of bounds write
			\param val uint16_t to write
		*/
		void WriteBE16(uint16_t val);

		/*! Write a uint32_t to the current cursor position, explicitly as big endian

		    \throws WriteException on out of bounds write
			\param val uint32_t to write
		*/
		void WriteBE32(uint32_t val);

		/*! Write a uint64_t to the current cursor position, explicitly as big endian

		    \throws WriteException on out of bounds write
			\param val uint64_t to write
		*/
		void WriteBE64(uint64_t val);

		/*! Write bytes from an address to the current cursor position

			\param src Address to read the bytes from
			\param len Amount of bytes to write
		 	\return Whether the write succeeded
		*/
		bool TryWrite(const void* src, size_t len);

		/*! Write from a DataBuffer to the current cursor position

			\param buf DataBuffer to write from
			\return Whether the write succeeded
		*/
		bool TryWrite(const DataBuffer& buf);

		/*! Write a string to the current cursor position

			\param str String to write
			\return Whether the write succeeded
		*/
		bool TryWrite(const std::string& str);

		/*! Write a uint8_t to the current cursor position

			\param val uint8_t to write
			\return Whether the write succeeded
		*/
		bool TryWrite8(uint8_t val);

		/*! Write a uint16_t to the current cursor position

			\param val uint16_t to write
			\return Whether the write succeeded
		*/
		bool TryWrite16(uint16_t val);

		/*! Write a uint32_t to the current cursor position

			\param val uint32_t to write
			\return Whether the write succeeded
		*/
		bool TryWrite32(uint32_t val);

		/*! Write a uint64_t to the current cursor position

			\param val uint64_t to write
			\return Whether the write succeeded
		*/
		bool TryWrite64(uint64_t val);
		bool TryWriteLE16(uint16_t val);
		bool TryWriteLE32(uint32_t val);
		bool TryWriteLE64(uint64_t val);
		bool TryWriteBE16(uint16_t val);
		bool TryWriteBE32(uint32_t val);
		bool TryWriteBE64(uint64_t val);

		/*! Get the current cursor position

			\return The current cursor position
		*/
		uint64_t GetOffset() const;

		/*! Set the current cursor position

			\param offset The new cursor position
		*/
		void Seek(uint64_t offset);

		/*! Set the cursor position relative to the current cursor position

			\param offset Offset to the current cursor position
		*/
		void SeekRelative(int64_t offset);
	};

	/*!
		\ingroup transform
	*/
	struct TransformParameter
	{
		std::string name, longName;
		size_t fixedLength;  // Variable length if zero
	};

	/*! Allows users to implement custom transformations.

	    New transformations may be added at runtime, so an instance of a transform is created like

		\code{.cpp}

	 	DataBuffer inputData = binaryView->ReadBuffer(0, 32); // Read the first 32 bytes of the file
	 	DataBuffer outputDataHash;

		Transform::GetByName("SHA512")->Encode(inputData, outputDataHash); // Writes the SHA512 hash to outputDataHash

		\endcode

	 	Getting a list of registered transforms:

	 	<b> From the interactive python console: </b>
	 	\code{.py}
	 	list(Transform)
	 	\endcode

	 	<b> At Runtime: </b>
	 	\code{.cpp}
	    std::vector<Ref<Transform>> registeredTypes = Transform::GetTransformTypes();
	 	\endcode

		\ingroup transform
	*/
	class Transform : public StaticCoreRefCountObject<BNTransform>
	{
	  protected:
		BNTransformType m_typeForRegister;
		std::string m_nameForRegister, m_longNameForRegister, m_groupForRegister;

		Transform(BNTransform* xform);

		static BNTransformParameterInfo* GetParametersCallback(void* ctxt, size_t* count);
		static void FreeParametersCallback(BNTransformParameterInfo* params, size_t count);
		static bool DecodeCallback(
		    void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);
		static bool EncodeCallback(
		    void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);

		static std::vector<TransformParameter> EncryptionKeyParameters(size_t fixedKeyLength = 0);
		static std::vector<TransformParameter> EncryptionKeyAndIVParameters(
		    size_t fixedKeyLength = 0, size_t fixedIVLength = 0);

	  public:
		Transform(BNTransformType type, const std::string& name, const std::string& longName, const std::string& group);

		static void Register(Transform* xform);
		static Ref<Transform> GetByName(const std::string& name);
		static std::vector<Ref<Transform>> GetTransformTypes();

		BNTransformType GetType() const;
		std::string GetName() const;
		std::string GetLongName() const;
		std::string GetGroup() const;

		virtual std::vector<TransformParameter> GetParameters() const;

		virtual bool Decode(const DataBuffer& input, DataBuffer& output,
		    const std::map<std::string, DataBuffer>& params = std::map<std::string, DataBuffer>());
		virtual bool Encode(const DataBuffer& input, DataBuffer& output,
		    const std::map<std::string, DataBuffer>& params = std::map<std::string, DataBuffer>());
	};

	/*!
		\ingroup transform
	*/
	class CoreTransform : public Transform
	{
	  public:
		CoreTransform(BNTransform* xform);
		virtual std::vector<TransformParameter> GetParameters() const override;

		virtual bool Decode(const DataBuffer& input, DataBuffer& output,
		    const std::map<std::string, DataBuffer>& params = std::map<std::string, DataBuffer>()) override;
		virtual bool Encode(const DataBuffer& input, DataBuffer& output,
		    const std::map<std::string, DataBuffer>& params = std::map<std::string, DataBuffer>()) override;
	};

	struct InstructionInfo : public BNInstructionInfo
	{
		InstructionInfo();
		void AddBranch(BNBranchType type, uint64_t target = 0, Architecture* arch = nullptr, bool hasDelaySlot = false);
	};

	struct NameAndType
	{
		std::string name;
		Confidence<Ref<Type>> type;

		NameAndType() {}
		NameAndType(const Confidence<Ref<Type>>& t) : type(t) {}
		NameAndType(const std::string& n, const Confidence<Ref<Type>>& t) : name(n), type(t) {}
	};

	class Function;
	class LowLevelILFunction;
	class MediumLevelILFunction;
	class HighLevelILFunction;
	class LanguageRepresentationFunction;
	class FunctionRecognizer;
	class CallingConvention;
	class RelocationHandler;

	typedef size_t ExprId;

	/*! The Architecture class is the base class for all CPU architectures. This provides disassembly, assembly,
	    patching, and IL translation lifting for a given architecture.

	    \ingroup architectures
	*/
	class Architecture : public StaticCoreRefCountObject<BNArchitecture>
	{
	  protected:
		std::string m_nameForRegister;

		Architecture(BNArchitecture* arch);

		static void InitCallback(void* ctxt, BNArchitecture* obj);
		static BNEndianness GetEndiannessCallback(void* ctxt);
		static size_t GetAddressSizeCallback(void* ctxt);
		static size_t GetDefaultIntegerSizeCallback(void* ctxt);
		static size_t GetInstructionAlignmentCallback(void* ctxt);
		static size_t GetMaxInstructionLengthCallback(void* ctxt);
		static size_t GetOpcodeDisplayLengthCallback(void* ctxt);
		static BNArchitecture* GetAssociatedArchitectureByAddressCallback(void* ctxt, uint64_t* addr);
		static bool GetInstructionInfoCallback(
		    void* ctxt, const uint8_t* data, uint64_t addr, size_t maxLen, BNInstructionInfo* result);
		static bool GetInstructionTextCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t* len,
		    BNInstructionTextToken** result, size_t* count);
		static void FreeInstructionTextCallback(BNInstructionTextToken* tokens, size_t count);
		static bool GetInstructionLowLevelILCallback(
		    void* ctxt, const uint8_t* data, uint64_t addr, size_t* len, BNLowLevelILFunction* il);
		static char* GetRegisterNameCallback(void* ctxt, uint32_t reg);
		static char* GetFlagNameCallback(void* ctxt, uint32_t flag);
		static char* GetFlagWriteTypeNameCallback(void* ctxt, uint32_t flags);
		static char* GetSemanticFlagClassNameCallback(void* ctxt, uint32_t semClass);
		static char* GetSemanticFlagGroupNameCallback(void* ctxt, uint32_t semGroup);
		static uint32_t* GetFullWidthRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetAllRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetAllFlagsCallback(void* ctxt, size_t* count);
		static uint32_t* GetAllFlagWriteTypesCallback(void* ctxt, size_t* count);
		static uint32_t* GetAllSemanticFlagClassesCallback(void* ctxt, size_t* count);
		static uint32_t* GetAllSemanticFlagGroupsCallback(void* ctxt, size_t* count);
		static BNFlagRole GetFlagRoleCallback(void* ctxt, uint32_t flag, uint32_t semClass);
		static uint32_t* GetFlagsRequiredForFlagConditionCallback(
		    void* ctxt, BNLowLevelILFlagCondition cond, uint32_t semClass, size_t* count);
		static uint32_t* GetFlagsRequiredForSemanticFlagGroupCallback(void* ctxt, uint32_t semGroup, size_t* count);
		static BNFlagConditionForSemanticClass* GetFlagConditionsForSemanticFlagGroupCallback(
		    void* ctxt, uint32_t semGroup, size_t* count);
		static void FreeFlagConditionsForSemanticFlagGroupCallback(
		    void* ctxt, BNFlagConditionForSemanticClass* conditions);
		static uint32_t* GetFlagsWrittenByFlagWriteTypeCallback(void* ctxt, uint32_t writeType, size_t* count);
		static uint32_t GetSemanticClassForFlagWriteTypeCallback(void* ctxt, uint32_t writeType);
		static size_t GetFlagWriteLowLevelILCallback(void* ctxt, BNLowLevelILOperation op, size_t size,
		    uint32_t flagWriteType, uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount,
		    BNLowLevelILFunction* il);
		static size_t GetFlagConditionLowLevelILCallback(
		    void* ctxt, BNLowLevelILFlagCondition cond, uint32_t semClass, BNLowLevelILFunction* il);
		static size_t GetSemanticFlagGroupLowLevelILCallback(void* ctxt, uint32_t semGroup, BNLowLevelILFunction* il);
		static void FreeRegisterListCallback(void* ctxt, uint32_t* regs);
		static void GetRegisterInfoCallback(void* ctxt, uint32_t reg, BNRegisterInfo* result);
		static uint32_t GetStackPointerRegisterCallback(void* ctxt);
		static uint32_t GetLinkRegisterCallback(void* ctxt);
		static uint32_t* GetGlobalRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetSystemRegistersCallback(void* ctxt, size_t* count);

		static char* GetRegisterStackNameCallback(void* ctxt, uint32_t regStack);
		static uint32_t* GetAllRegisterStacksCallback(void* ctxt, size_t* count);
		static void GetRegisterStackInfoCallback(void* ctxt, uint32_t regStack, BNRegisterStackInfo* result);

		static char* GetIntrinsicNameCallback(void* ctxt, uint32_t intrinsic);
		static uint32_t* GetAllIntrinsicsCallback(void* ctxt, size_t* count);
		static BNNameAndType* GetIntrinsicInputsCallback(void* ctxt, uint32_t intrinsic, size_t* count);
		static void FreeNameAndTypeListCallback(void* ctxt, BNNameAndType* nt, size_t count);
		static BNTypeWithConfidence* GetIntrinsicOutputsCallback(void* ctxt, uint32_t intrinsic, size_t* count);
		static void FreeTypeListCallback(void* ctxt, BNTypeWithConfidence* types, size_t count);

		static bool CanAssembleCallback(void* ctxt);
		static bool AssembleCallback(void* ctxt, const char* code, uint64_t addr, BNDataBuffer* result, char** errors);
		static bool IsNeverBranchPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		static bool IsAlwaysBranchPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		static bool IsInvertBranchPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		static bool IsSkipAndReturnZeroPatchAvailableCallback(
		    void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		static bool IsSkipAndReturnValuePatchAvailableCallback(
		    void* ctxt, const uint8_t* data, uint64_t addr, size_t len);

		static bool ConvertToNopCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len);
		static bool AlwaysBranchCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len);
		static bool InvertBranchCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len);
		static bool SkipAndReturnValueCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len, uint64_t value);

		virtual void Register(BNCustomArchitecture* callbacks);

	  public:
		Architecture(const std::string& name);

		/*! Register an architecture

			\param arch Architecture to register
		*/
		static void Register(Architecture* arch);

		/*! Get an Architecture by name

			\param name Name of the architecture
			\return The architecture, if it was found.
		*/
		static Ref<Architecture> GetByName(const std::string& name);

		/*! Get the list of registered Architectures

			\return The list of registered architectures
		*/
		static std::vector<Ref<Architecture>> GetList();

		/*! Get the name of this architecture

			\return The name of this architecture
		*/
		std::string GetName() const;

		/*! Get the default endianness for this architecture

			\return The default endianness for this architecture
		*/
		virtual BNEndianness GetEndianness() const = 0;

		/*! Get the address size for this architecture

			\return The address size for this architecture
		*/
		virtual size_t GetAddressSize() const = 0;

		/*! Get the default integer size for this architecture

			\return The default integer size for this architecture
		*/
		virtual size_t GetDefaultIntegerSize() const;
		virtual size_t GetInstructionAlignment() const;

		/*! Get the maximum instruction length

			\return The maximum instruction length
		*/
		virtual size_t GetMaxInstructionLength() const;
		virtual size_t GetOpcodeDisplayLength() const;

		virtual Ref<Architecture> GetAssociatedArchitectureByAddress(uint64_t& addr);

		/*! Retrieves an InstructionInfo struct for the instruction at the given virtual address

		 	\note Architecture subclasses should implement this method.
		 	\note The instruction info object should always set the InstructionInfo.length to the instruction length, \
					and the branches of the proper types should be added if the instruction is a branch.

			If the instruction is a branch instruction architecture plugins should add a branch of the proper type:

				===================== ===================================================
				BNBranchType          Description
				===================== ===================================================
				UnconditionalBranch   Branch will always be taken
				FalseBranch           False branch condition
				TrueBranch            True branch condition
				CallDestination       Branch is a call instruction (Branch with Link)
				FunctionReturn        Branch returns from a function
				SystemCall            System call instruction
				IndirectBranch        Branch destination is a memory address or register
				UnresolvedBranch      Branch destination is an unknown address
				===================== ===================================================

			\param[in] data pointer to the instruction data to retrieve info for
		    \param[in] addr address of the instruction data to retrieve info for
			\param[in] maxLen Maximum length of the instruction data to read
			\param[out] result Retrieved instruction info
			\return Whether instruction info was successfully retrieved.
		*/
		virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) = 0;

		/*! Retrieves a list of InstructionTextTokens

			\param[in] data pointer to the instruction data to retrieve text for
			\param[in] addr address of the instruction data to retrieve text for
			\param[out] len will be written to with the length of the instruction data which was translated
			\param[out] result
			\return Whether instruction info was successfully retrieved.
		*/
		virtual bool GetInstructionText(
		    const uint8_t* data, uint64_t addr, size_t& len, std::vector<InstructionTextToken>& result) = 0;

		/*! Translates an instruction at addr and appends it onto the LowLevelILFunction& il.

		    \note Architecture subclasses should implement this method.

		    \param[in] data pointer to the instruction data to be translated
		    \param[in] addr address of the instruction data to be translated
		    \param[out] len will be written to with the length of the instruction data which was translated
		    \param[in,out] il the LowLevelILFunction to appended to.
		*/
		virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il);

		/*! Gets a register name from a register index.

			\param reg Register index
			\return The register name
		*/
		virtual std::string GetRegisterName(uint32_t reg);

		/*! Gets a flag name from a flag index

			\param flag Flag index
			\return Flag name
		*/
		virtual std::string GetFlagName(uint32_t flag);

		/*! Gets the flag write type name for the given flag.

			\param flags flag
			\return Flag name
		*/
		virtual std::string GetFlagWriteTypeName(uint32_t flags);

		/*! Gets the name of a semantic flag class from the index.

			\param semClass Semantic class index
			\return The name of the semantic flag class
		*/
		virtual std::string GetSemanticFlagClassName(uint32_t semClass);

		/*! Gets the name of a semantic flag group from the index.

			\param semGroup Semantic flag group index
			\return Semantic flag group name
		*/
		virtual std::string GetSemanticFlagGroupName(uint32_t semGroup);

		/*! Get the list of full width register indices

			\return The list of full width register indices
		*/
		virtual std::vector<uint32_t> GetFullWidthRegisters();

		/*! Get the list of all register indices

			\return The list of all register indices
		*/
		virtual std::vector<uint32_t> GetAllRegisters();

		/*! Get the list of all flag indices

			\return The list of all flag indices
		*/
		virtual std::vector<uint32_t> GetAllFlags();

		/*! Get the list of all flag write type indices

			\return The list of all flag write type indices
		*/
		virtual std::vector<uint32_t> GetAllFlagWriteTypes();

		/*! Get the list of all semantic flag class indices

			\return The list of all semantic flag class indices
		*/
		virtual std::vector<uint32_t> GetAllSemanticFlagClasses();

		/*! Get the list of all semantic flag group indices

			\return The list of all semantic flag group indices
		*/
		virtual std::vector<uint32_t> GetAllSemanticFlagGroups();

		/*! Get the role of a given flag.

			\param flag Flag index
			\param semClass Optional semantic flag class
			\return Flag role
		*/
		virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t semClass = 0);
		virtual std::vector<uint32_t> GetFlagsRequiredForFlagCondition(
		    BNLowLevelILFlagCondition cond, uint32_t semClass = 0);
		virtual std::vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup);
		virtual std::map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(uint32_t semGroup);
		virtual std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType);
		virtual uint32_t GetSemanticClassForFlagWriteType(uint32_t writeType);
		virtual ExprId GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
		    uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il);
		ExprId GetDefaultFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, BNFlagRole role,
		    BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il);
		virtual ExprId GetFlagConditionLowLevelIL(
		    BNLowLevelILFlagCondition cond, uint32_t semClass, LowLevelILFunction& il);
		ExprId GetDefaultFlagConditionLowLevelIL(
		    BNLowLevelILFlagCondition cond, uint32_t semClass, LowLevelILFunction& il);
		virtual ExprId GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il);

		/*! Get the register info for a given register index

			\param reg Register index
			\return Register info
		*/
		virtual BNRegisterInfo GetRegisterInfo(uint32_t reg);

		/*! Get the register index corresponding to the stack pointer (SP)

			\return The register index corresponding to the stack pointer
		*/
		virtual uint32_t GetStackPointerRegister();

		/*! Get the register index corresponding to the link register (LR)

			\return The register index corresponding to the link register
		*/
		virtual uint32_t GetLinkRegister();
		virtual std::vector<uint32_t> GetGlobalRegisters();
		bool IsGlobalRegister(uint32_t reg);

		/*! Get the list of system register indices

			\return The list of system register indices
		*/
		virtual std::vector<uint32_t> GetSystemRegisters();

		/*! Check whether a register is a system register

			\param reg Register index
			\return Whether a register is a system register
		*/
		bool IsSystemRegister(uint32_t reg);

		/*! Returns a list of register indices that are modified when \c reg is written to.

			\param reg Register index
			\return List of register indices modified on write.
		*/
		std::vector<uint32_t> GetModifiedRegistersOnWrite(uint32_t reg);

		/*! Get a register index by its name

			\param name Name of the register
			\return Index of the register
		*/
		uint32_t GetRegisterByName(const std::string& name);

		/*! Get a register stack name from a register stack number.

			\param regStack Register stack number
			\return The corresponding register string
		*/
		virtual std::string GetRegisterStackName(uint32_t regStack);
		virtual std::vector<uint32_t> GetAllRegisterStacks();
		virtual BNRegisterStackInfo GetRegisterStackInfo(uint32_t regStack);
		uint32_t GetRegisterStackForRegister(uint32_t reg);

		/*! Gets an intrinsic name from an intrinsic number.

			\param intrinsic Intrinsic number
			\return The corresponding intrinsic string
		*/
		virtual std::string GetIntrinsicName(uint32_t intrinsic);
		virtual std::vector<uint32_t> GetAllIntrinsics();
		virtual std::vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic);
		virtual std::vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic);

		/*! Check whether this architecture can assemble instructions

			\return Whether this architecture can assemble instructions
		*/
		virtual bool CanAssemble();

		/*! Converts the string of assembly instructions \c code loaded at virtual address \c addr to the
			byte representation of those instructions.

			\param[in] code String representation of the instructions to be assembled
			\param[in] addr Address of the instructions
			\param[out] result DataBuffer containing the compiled bytes
			\param[out] errors Any errors that occurred during assembly
			\return Whether assembly was successful
		*/
		virtual bool Assemble(const std::string& code, uint64_t addr, DataBuffer& result, std::string& errors);

		/*! Returns true if the instruction at \c addr can be patched to never branch.

		    \note This is used in the UI to determine if "never branch" should be displayed in the right-click context
		    menu when right-clicking on an instruction.

		    \param data Buffer of bytes to check
		    \param addr the virtual address of the bytes, to be used when assembling
		    \param len amount of bytes to be checked
		    \return If the never branch patch is available
		*/
		virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! Returns true if the instruction at addr can be patched to always branch.

		    \note This is used in the UI to determine if "always branch" should be displayed in the right-click context
		    menu when right-clicking on an instruction.

		    \param data Buffer of bytes to check
		    \param addr the address of the instruction in question
		    \param len amount of bytes to be checked
		    \return If the always branch patch is available
		*/
		virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! Returns true if the instruction at addr can be patched to invert the branch.

		    \note This is used in the UI to determine if "invert branch" should be displayed in the right-click context
		    menu when right-clicking on an instruction.

		    \param data Buffer of bytes to check
		    \param addr the address of the instruction in question
			\param len amount of bytes to be checked
			\return If the invert branch patch is available
		*/
		virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! Checks if the instruction at addr is a call that can be patched to return zero.

			\note This is used in the UI to determine if "skip and return zero" should be displayed in the
		    right-click context menu when right-clicking on an instruction.

		    \param data Buffer of bytes to check
		    \param addr the address of the instruction in question
		    \param len amount of bytes to be checked
			\return If the skip and return zero patch is available
		*/
		virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! Checks if the instruction at addr is a call that can be patched to return a value.

		    \note This is used in the UI to determine if "skip and return value" should be displayed in the
		    right-click context menu when right-clicking on an instruction.

		    \param data Buffer of bytes to check
		    \param addr the address of the instruction in question
		    \param len amount of bytes to be checked
			\return If the skip and return value patch is available
		*/
		virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! Converts the instruction at addr to a no-operation instruction

		    \param[in,out] data Buffer of bytes to convert
		    \param[in] addr the address of the instruction to be converted
		    \param[in] len Length of the bytes to be converted
		    \return Whether the conversion was successful
		*/
		virtual bool ConvertToNop(uint8_t* data, uint64_t addr, size_t len);

		/*! Converts the conditional branch instruction at addr to an unconditional branch.

			\note This is called when the right-click context menu item "always branch" is selected in the UI.

		    \param[in,out] data Buffer of bytes to convert
		    \param[in] addr the address of the instruction to be converted
		    \param[in] len Length of the bytes to be converted
		    \return Whether the conversion was successful
		*/
		virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len);

		/*! InvertBranch converts the conditional branch instruction at addr to its invert.

			\note This is called when the right-click context menu item "invert branch" is selected in the UI.

		    \param[in,out] data Buffer of bytes to convert
		    \param[in] addr the address of the instruction to be converted
		    \param[in] len Length of the bytes to be converted
		    \return Whether the conversion was successful
		*/
		virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len);

		/*! SkipAndReturnValue converts the call instruction at addr to an instruction that simulates that call
		    returning a value.

		    \note This is called when the right-click context menu item "skip and return value" is selected in the UI.

		    \param[in,out] data Buffer of bytes to convert
		    \param[in] addr the address of the instruction to be converted
		    \param[in] len Length of the bytes to be converted
		    \param[in] value Value to be returned
		    \return Whether the conversion was successful
		*/
		virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value);

		void RegisterFunctionRecognizer(FunctionRecognizer* recog);
		void RegisterRelocationHandler(const std::string& viewName, RelocationHandler* handler);
		Ref<RelocationHandler> GetRelocationHandler(const std::string& viewName);

		// These three binary view type constant APIs are deprecated and should no longer be used. Their implementations
		// have been removed, and they now have no effects.
		/*! \deprecated This API has been deprecated. The implementation has been removed, and this function no
		 		longer has any effect
		*/
		bool IsBinaryViewTypeConstantDefined(const std::string& type, const std::string& name);
		/*! \deprecated This API has been deprecated. The implementation has been removed, and this function no
		 		longer has any effect
		*/
		uint64_t GetBinaryViewTypeConstant(const std::string& type, const std::string& name, uint64_t defaultValue = 0);
		/*! \deprecated This API has been deprecated. The implementation has been removed, and this function no
		 		longer has any effect
		*/
		void SetBinaryViewTypeConstant(const std::string& type, const std::string& name, uint64_t value);

		/*! Register a calling convention with this architecture

			\param cc calling convention to register
		*/
		void RegisterCallingConvention(CallingConvention* cc);

		/*! List of registered calling conventions

			\return The list of registered calling conventions
		*/
		std::vector<Ref<CallingConvention>> GetCallingConventions();

		/*! Get a calling convention by name

			\param name Name of the calling convention
			\return The calling convention
		*/
		Ref<CallingConvention> GetCallingConventionByName(const std::string& name);

		/*! Set the default calling convention

			\param cc The default calling convention
		*/
		void SetDefaultCallingConvention(CallingConvention* cc);

		/*! Set the cdecl calling convention

			\param cc The cdecl calling convention
		*/
		void SetCdeclCallingConvention(CallingConvention* cc);

		/*! Set the stdcall calling convention

			\param cc The stdcall calling convention
		*/
		void SetStdcallCallingConvention(CallingConvention* cc);

		/*! Set the fastcall calling convention

			\param cc The fastcall calling convention
		*/
		void SetFastcallCallingConvention(CallingConvention* cc);

		/*! Get the default calling convention

			\return The default calling convention
		*/
		Ref<CallingConvention> GetDefaultCallingConvention();

		/*! Get the cdecl calling convention

			\return The cdecl calling convention
		*/
		Ref<CallingConvention> GetCdeclCallingConvention();

		/*! Get the stdcall calling convention

			\return The stdcall calling convention
		*/
		Ref<CallingConvention> GetStdcallCallingConvention();

		/*! Get the fastcall calling convention

			\return The fastcall calling convention
		*/
		Ref<CallingConvention> GetFastcallCallingConvention();

		/*! Get the Architecture standalone platform

			\return Architecture standalone platform
		*/
		Ref<Platform> GetStandalonePlatform();
		void AddArchitectureRedirection(Architecture* from, Architecture* to);
	};

	/*!

	 	\ingroup architectures
	*/
	class CoreArchitecture : public Architecture
	{
	  public:
		CoreArchitecture(BNArchitecture* arch);
		virtual BNEndianness GetEndianness() const override;
		virtual size_t GetAddressSize() const override;
		virtual size_t GetDefaultIntegerSize() const override;
		virtual size_t GetInstructionAlignment() const override;
		virtual size_t GetMaxInstructionLength() const override;
		virtual size_t GetOpcodeDisplayLength() const override;
		virtual Ref<Architecture> GetAssociatedArchitectureByAddress(uint64_t& addr) override;
		virtual bool GetInstructionInfo(
		    const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override;
		virtual bool GetInstructionText(
		    const uint8_t* data, uint64_t addr, size_t& len, std::vector<InstructionTextToken>& result) override;
		virtual bool GetInstructionLowLevelIL(
		    const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override;
		virtual std::string GetRegisterName(uint32_t reg) override;
		virtual std::string GetFlagName(uint32_t flag) override;
		virtual std::string GetFlagWriteTypeName(uint32_t flags) override;

		virtual std::string GetSemanticFlagClassName(uint32_t semClass) override;
		virtual std::string GetSemanticFlagGroupName(uint32_t semGroup) override;
		virtual std::vector<uint32_t> GetFullWidthRegisters() override;
		virtual std::vector<uint32_t> GetAllRegisters() override;
		virtual std::vector<uint32_t> GetAllFlags() override;
		virtual std::vector<uint32_t> GetAllFlagWriteTypes() override;
		virtual std::vector<uint32_t> GetAllSemanticFlagClasses() override;
		virtual std::vector<uint32_t> GetAllSemanticFlagGroups() override;
		virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t semClass = 0) override;
		virtual std::vector<uint32_t> GetFlagsRequiredForFlagCondition(
		    BNLowLevelILFlagCondition cond, uint32_t semClass = 0) override;
		virtual std::vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup) override;
		virtual std::map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(
		    uint32_t semGroup) override;
		virtual std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType) override;
		virtual uint32_t GetSemanticClassForFlagWriteType(uint32_t writeType) override;
		virtual ExprId GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
		    uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il) override;
		virtual ExprId GetFlagConditionLowLevelIL(
		    BNLowLevelILFlagCondition cond, uint32_t semClass, LowLevelILFunction& il) override;
		virtual ExprId GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il) override;
		virtual BNRegisterInfo GetRegisterInfo(uint32_t reg) override;
		virtual uint32_t GetStackPointerRegister() override;
		virtual uint32_t GetLinkRegister() override;
		virtual std::vector<uint32_t> GetGlobalRegisters() override;
		virtual std::vector<uint32_t> GetSystemRegisters() override;

		virtual std::string GetRegisterStackName(uint32_t regStack) override;
		virtual std::vector<uint32_t> GetAllRegisterStacks() override;
		virtual BNRegisterStackInfo GetRegisterStackInfo(uint32_t regStack) override;

		virtual std::string GetIntrinsicName(uint32_t intrinsic) override;
		virtual std::vector<uint32_t> GetAllIntrinsics() override;
		virtual std::vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override;
		virtual std::vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic) override;

		virtual bool CanAssemble() override;
		virtual bool Assemble(const std::string& code, uint64_t addr, DataBuffer& result, std::string& errors) override;

		virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;

		virtual bool ConvertToNop(uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value) override;
	};

	/*!

		\ingroup architectures
	*/
	class ArchitectureExtension : public Architecture
	{
	  protected:
		Ref<Architecture> m_base;

		virtual void Register(BNCustomArchitecture* callbacks) override;

	  public:
		ArchitectureExtension(const std::string& name, Architecture* base);

		Ref<Architecture> GetBaseArchitecture() const { return m_base; }

		virtual BNEndianness GetEndianness() const override;
		virtual size_t GetAddressSize() const override;
		virtual size_t GetDefaultIntegerSize() const override;
		virtual size_t GetInstructionAlignment() const override;
		virtual size_t GetMaxInstructionLength() const override;
		virtual size_t GetOpcodeDisplayLength() const override;
		virtual Ref<Architecture> GetAssociatedArchitectureByAddress(uint64_t& addr) override;
		virtual bool GetInstructionInfo(
		    const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override;
		virtual bool GetInstructionText(
		    const uint8_t* data, uint64_t addr, size_t& len, std::vector<InstructionTextToken>& result) override;
		virtual bool GetInstructionLowLevelIL(
		    const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override;
		virtual std::string GetRegisterName(uint32_t reg) override;
		virtual std::string GetFlagName(uint32_t flag) override;
		virtual std::string GetFlagWriteTypeName(uint32_t flags) override;
		virtual std::string GetSemanticFlagClassName(uint32_t semClass) override;
		virtual std::string GetSemanticFlagGroupName(uint32_t semGroup) override;
		virtual std::vector<uint32_t> GetFullWidthRegisters() override;
		virtual std::vector<uint32_t> GetAllRegisters() override;
		virtual std::vector<uint32_t> GetAllFlags() override;
		virtual std::vector<uint32_t> GetAllFlagWriteTypes() override;
		virtual std::vector<uint32_t> GetAllSemanticFlagClasses() override;
		virtual std::vector<uint32_t> GetAllSemanticFlagGroups() override;
		virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t semClass = 0) override;
		virtual std::vector<uint32_t> GetFlagsRequiredForFlagCondition(
		    BNLowLevelILFlagCondition cond, uint32_t semClass = 0) override;
		virtual std::vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup) override;
		virtual std::map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(
		    uint32_t semGroup) override;
		virtual std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType) override;
		virtual uint32_t GetSemanticClassForFlagWriteType(uint32_t writeType) override;
		virtual ExprId GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
		    uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il) override;
		virtual ExprId GetFlagConditionLowLevelIL(
		    BNLowLevelILFlagCondition cond, uint32_t semClass, LowLevelILFunction& il) override;
		virtual ExprId GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il) override;
		virtual BNRegisterInfo GetRegisterInfo(uint32_t reg) override;
		virtual uint32_t GetStackPointerRegister() override;
		virtual uint32_t GetLinkRegister() override;
		virtual std::vector<uint32_t> GetGlobalRegisters() override;
		virtual std::vector<uint32_t> GetSystemRegisters() override;

		virtual std::string GetRegisterStackName(uint32_t regStack) override;
		virtual std::vector<uint32_t> GetAllRegisterStacks() override;
		virtual BNRegisterStackInfo GetRegisterStackInfo(uint32_t regStack) override;

		virtual std::string GetIntrinsicName(uint32_t intrinsic) override;
		virtual std::vector<uint32_t> GetAllIntrinsics() override;
		virtual std::vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override;
		virtual std::vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic) override;

		virtual bool CanAssemble() override;
		virtual bool Assemble(const std::string& code, uint64_t addr, DataBuffer& result, std::string& errors) override;

		virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;

		virtual bool ConvertToNop(uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value) override;
	};

	/*!

		\ingroup architectures
	*/
	class ArchitectureHook : public CoreArchitecture
	{
	  protected:
		Ref<Architecture> m_base;

		virtual void Register(BNCustomArchitecture* callbacks) override;

	  public:
		ArchitectureHook(Architecture* base);
	};

	class Structure;
	class NamedTypeReference;
	class Enumeration;

	/*!
		\ingroup variable
	*/
	struct Variable : public BNVariable
	{
		Variable();
		Variable(BNVariableSourceType type, uint32_t index, uint64_t storage);
		Variable(BNVariableSourceType type, uint64_t storage);
		Variable(const BNVariable& var);
		Variable(const Variable& var);

		Variable& operator=(const Variable& var);

		bool operator==(const Variable& var) const;
		bool operator!=(const Variable& var) const;
		bool operator<(const Variable& var) const;

		uint64_t ToIdentifier() const;
		static Variable FromIdentifier(uint64_t id);
	};

	struct VariableReferenceSource
	{
		Variable var;
		ILReferenceSource source;
	};

	struct FunctionParameter
	{
		std::string name;
		Confidence<Ref<Type>> type;
		bool defaultLocation;
		Variable location;

		FunctionParameter() = default;
		FunctionParameter(const std::string& name, Confidence<Ref<Type>> type): name(name), type(type), defaultLocation(true)
		{}

		FunctionParameter(const std::string& name, const Confidence<Ref<Type>>& type, bool defaultLocation,
		    const Variable& location):
		    name(name), type(type), defaultLocation(defaultLocation), location(location)
		{}
	};

	struct QualifiedNameAndType
	{
		QualifiedName name;
		Ref<Type> type;

		QualifiedNameAndType() = default;
		QualifiedNameAndType(const std::string& name, const Ref<Type>& type): name(name), type(type)
		{}
		QualifiedNameAndType(const QualifiedName& name, const Ref<Type>& type): name(name), type(type)
		{}

		bool operator<(const QualifiedNameAndType& other) const
		{
			return name < other.name;
		}
	};

	struct TypeAndId
	{
		std::string id;
		Ref<Type> type;

		TypeAndId() = default;
		TypeAndId(const std::string& id, const Ref<Type>& type): id(id), type(type)
		{}
	};

	/*!
		\ingroup typeparser
	*/
	struct ParsedType
	{
		QualifiedName name;
		Ref<Type> type;
		bool isUser;

		ParsedType() = default;
		ParsedType(const std::string& name, const Ref<Type>& type, bool isUser): name(name), type(type), isUser(isUser)
		{}
		ParsedType(const QualifiedName& name, const Ref<Type>& type, bool isUser): name(name), type(type), isUser(isUser)
		{}

		bool operator<(const ParsedType& other) const
		{
			if (isUser != other.isUser)
				return isUser;
			return name < other.name;
		}
	};

	/*!
		\ingroup typeparser
	*/
	struct TypeParserResult
	{
		std::vector<ParsedType> types;
		std::vector<ParsedType> variables;
		std::vector<ParsedType> functions;
	};

	/*!
		\ingroup typeparser
	*/
	struct TypeParserError
	{
		BNTypeParserErrorSeverity severity;
		std::string message;
		std::string fileName;
		uint64_t line;
		uint64_t column;
	};

	/*!
		\ingroup types
	*/
	class Type : public CoreRefCountObject<BNType, BNNewTypeReference, BNFreeType>
	{
	  public:
		Type(BNType* type);

		bool operator==(const Type& other);
		bool operator!=(const Type& other);


		/*! Retrieve the Type Class for this Structure

		 	One of:

		        VoidTypeClass
				BoolTypeClass
				IntegerTypeClass
				FloatTypeClass
				StructureTypeClass
				EnumerationTypeClass
				PointerTypeClass
				ArrayTypeClass
				FunctionTypeClass
				VarArgsTypeClass
				ValueTypeClass
				NamedTypeReferenceClass
				WideCharTypeClass

		    \return The type class
		*/
		BNTypeClass GetClass() const;

		/*! Get the width in bytes of the Type

		    \return The type width
		*/
		uint64_t GetWidth() const;
		size_t GetAlignment() const;

		/*! Get the QualifiedName for the Type

		    \return The QualifiedName for the type
		*/
		QualifiedName GetTypeName() const;

		/*! Whether the type is signed
		*/
		Confidence<bool> IsSigned() const;

		/*! Whether the type is constant

		*/
		Confidence<bool> IsConst() const;
		Confidence<bool> IsVolatile() const; // Unimplemented!
		bool IsSystemCall() const;


		/*! Get the child type for this Type if one exists

		    \return The child type
		*/
		Confidence<Ref<Type>> GetChildType() const;

		/*! For Function Types, get the calling convention

		    \return The CallingConvention
		*/
		Confidence<Ref<CallingConvention>> GetCallingConvention() const;

		/*! For Function Types, get a list of parameters

		    \return A vector of FunctionParameters
		*/
		std::vector<FunctionParameter> GetParameters() const;

		/*! For Function Types, whether the Function has variadic arguments

		    \return Whether the function has variable arguments
		*/
		Confidence<bool> HasVariableArguments() const;

		/*! For Function Types, whether a function can return (is not marked noreturn)

		    \return Whether the function can return
		*/
		Confidence<bool> CanReturn() const;

		/*! For Structure Types, the underlying Structure

		    \return The underlying structure
		*/
		Ref<Structure> GetStructure() const;

		/*! For Enumeration Types, the underlying Enumeration

		    \return The underlying enumeration
		*/
		Ref<Enumeration> GetEnumeration() const;

		/*! For NamedTypeReference Types, the underlying NamedTypeReference

		    \return The underlying NamedTypeReference
		*/
		Ref<NamedTypeReference> GetNamedTypeReference() const;
		Confidence<BNMemberScope> GetScope() const; // Unimplemented!
		Confidence<int64_t> GetStackAdjustment() const;
		QualifiedName GetStructureName() const;
		Ref<NamedTypeReference> GetRegisteredName() const;
		uint32_t GetSystemCallNumber() const;
		BNIntegerDisplayType GetIntegerTypeDisplayType() const;

		uint64_t GetElementCount() const;
		uint64_t GetOffset() const;

		std::string GetString(Platform* platform = nullptr, BNTokenEscapingType escaping = NoTokenEscapingType) const;
		std::string GetTypeAndName(const QualifiedName& name, BNTokenEscapingType escaping = NoTokenEscapingType) const;
		std::string GetStringBeforeName(Platform* platform = nullptr, BNTokenEscapingType escaping = NoTokenEscapingType) const;
		std::string GetStringAfterName(Platform* platform = nullptr, BNTokenEscapingType escaping = NoTokenEscapingType) const;

		std::vector<InstructionTextToken> GetTokens(
		    Platform* platform = nullptr, uint8_t baseConfidence = BN_FULL_CONFIDENCE,
		    BNTokenEscapingType escaping = NoTokenEscapingType) const;
		std::vector<InstructionTextToken> GetTokensBeforeName(
		    Platform* platform = nullptr, uint8_t baseConfidence = BN_FULL_CONFIDENCE,
		    BNTokenEscapingType escaping = NoTokenEscapingType) const;
		std::vector<InstructionTextToken> GetTokensAfterName(
		    Platform* platform = nullptr, uint8_t baseConfidence = BN_FULL_CONFIDENCE,
		    BNTokenEscapingType escaping = NoTokenEscapingType) const;

		Ref<Type> Duplicate() const;


		/*! Create a "void" type

		    \return The created Type object
		*/
		static Ref<Type> VoidType();

		/*! Create a "bool" type

		    \return The created Type object
		*/
		static Ref<Type> BoolType();

		/*! Create a signed or unsigned integer with a set width

		    \param width Width of the Type in bytes
		    \param sign Whether the integer is a signed or unsigned type
		    \param altName Alternative name for the type
		    \return The created Type object
		*/
		static Ref<Type> IntegerType(size_t width, const Confidence<bool>& sign, const std::string& altName = "");

		/*! Create a float or double Type with a specified width

		    \param width Width of the Type in bytes
		    \param altName Alternative name for the type
		    \return The created Type object
		*/
		static Ref<Type> FloatType(size_t width, const std::string& altName = "");
		static Ref<Type> WideCharType(size_t width, const std::string& altName = "");

		/*! Create a Type object from a Structure object

		 	Structure objects can be generated using the StructureBuilder class.

		    \param strct Structure object
		    \return The created Type object
		*/
		static Ref<Type> StructureType(Structure* strct);
		static Ref<Type> NamedType(NamedTypeReference* ref, size_t width = 0, size_t align = 1,
		    const Confidence<bool>& cnst = Confidence<bool>(false, 0),
		    const Confidence<bool>& vltl = Confidence<bool>(false, 0));
		static Ref<Type> NamedType(const QualifiedName& name, Type* type);
		static Ref<Type> NamedType(const std::string& id, const QualifiedName& name, Type* type);
		static Ref<Type> NamedType(BinaryView* view, const QualifiedName& name);
		static Ref<Type> EnumerationType(Architecture* arch, Enumeration* enm, size_t width = 0,
		    const Confidence<bool>& isSigned = Confidence<bool>(false, 0));
		static Ref<Type> EnumerationType(
		    Enumeration* enm, size_t width, const Confidence<bool>& isSigned = Confidence<bool>(false, 0));

		/*! Create a Pointer type, which points to another Type

			\code{.cpp}
		 	// Creating a "char *" type
		 	auto arch = bv->GetDefaultArchitecture();
		    auto charPointerType = Type::PointerType(arch, Type::IntegerType(1, false));
		 	\endcode

			\param arch Architecture, used to calculate the proper pointer width
			\param type Type that this Type points to
			\param cnst Whether this type is const
			\param vltl Whether this type is volatile
			\param refType Reference Type, one of "PointerReferenceType", "ReferenceReferenceType", "RValueReferenceType", "NoReference"
			\return The created type
		*/
		static Ref<Type> PointerType(Architecture* arch, const Confidence<Ref<Type>>& type,
		    const Confidence<bool>& cnst = Confidence<bool>(false, 0),
		    const Confidence<bool>& vltl = Confidence<bool>(false, 0), BNReferenceType refType = PointerReferenceType);

		/*! Create a Pointer type, which points to another Type

			\code{.cpp}
			// Creating a "char *" type in a binary compiled for 64 bit address spaces
			auto charPointerType = Type::PointerType(8, Type::IntegerType(1, false));
			\endcode

			\param width Width of the pointer in bytes
			\param type Type that this type points to
			\param cnst Whether this type is const
			\param vltl Whether this type is volatile
			\param refType Reference Type, one of "PointerReferenceType", "ReferenceReferenceType", "RValueReferenceType", "NoReference"
			\return The created type
		*/
		static Ref<Type> PointerType(size_t width, const Confidence<Ref<Type>>& type,
		    const Confidence<bool>& cnst = Confidence<bool>(false, 0),
		    const Confidence<bool>& vltl = Confidence<bool>(false, 0), BNReferenceType refType = PointerReferenceType);

		/*! Create an Array Type

			\param type Type for Elements contained in this Array
			\param elem Number of elements
			\return The created Type
		*/
		static Ref<Type> ArrayType(const Confidence<Ref<Type>>& type, uint64_t elem);

		/*! Create a Function Type

			\code{.cpp}
		    Ref<Type> retType = Type::VoidType();

			std::vector<FunctionParameter> params
			auto cc = bv->GetDefaultPlatform()->GetDefaultCallingConvention();

		    params.push_back({"arg0",
				Type::IntegerType(8, false),
				true,
				Variable()});

		    auto functionType = Type::FunctionType(retType, cc, params);
		    \endcode

			\param returnValue Return value Type
			\param callingConvention Calling convention for the function
			\param params list of FunctionParameter s
			\param varArg Whether this function has variadic arguments, default false
			\param stackAdjust Stack adjustment for this function, default 0
			\return The created function types
		*/
		static Ref<Type> FunctionType(const Confidence<Ref<Type>>& returnValue,
		    const Confidence<Ref<CallingConvention>>& callingConvention, const std::vector<FunctionParameter>& params,
		    const Confidence<bool>& varArg = Confidence<bool>(false, 0),
		    const Confidence<int64_t>& stackAdjust = Confidence<int64_t>(0, 0));

		/*! Create a Function Type

			\code{.cpp}
		    Ref<Type> retType = Type::VoidType();

			std::vector<FunctionParameter> params
			auto cc = bv->GetDefaultPlatform()->GetDefaultCallingConvention();

		    params.push_back({"arg0",
				Type::IntegerType(8, false),
				true,
				Variable()});

		    auto functionType = Type::FunctionType(retType, cc, params);
		    \endcode

			\param returnValue Return value Type
			\param callingConvention Calling convention for the function
			\param params list of FunctionParameters
			\param varArg Whether this function has variadic arguments, default false
			\param stackAdjust Stack adjustment for this function, default 0
		 	\param regStackAdjust Register stack adjustmemt
		 	\param returnRegs Return registers
			\return The created function types
		*/
		static Ref<Type> FunctionType(const Confidence<Ref<Type>>& returnValue,
		    const Confidence<Ref<CallingConvention>>& callingConvention,
		    const std::vector<FunctionParameter>& params,
		    const Confidence<bool>& hasVariableArguments,
		    const Confidence<bool>& canReturn,
		    const Confidence<int64_t>& stackAdjust,
		    const std::map<uint32_t, Confidence<int32_t>>& regStackAdjust = std::map<uint32_t, Confidence<int32_t>>(),
		    const Confidence<std::vector<uint32_t>>& returnRegs = Confidence<std::vector<uint32_t>>(std::vector<uint32_t>(), 0),
		    BNNameType ft = NoNameType);

		static std::string GenerateAutoTypeId(const std::string& source, const QualifiedName& name);
		static std::string GenerateAutoDemangledTypeId(const QualifiedName& name);
		static std::string GetAutoDemangledTypeIdSource();
		static std::string GenerateAutoDebugTypeId(const QualifiedName& name);
		static std::string GetAutoDebugTypeIdSource();

		/*! Get this type wrapped in a Confidence template

			\param conf Confidence value between 0 and 255
			\return Confidence-wrapped Type
		*/
		Confidence<Ref<Type>> WithConfidence(uint8_t conf);

		/*! If this Type is a NamedTypeReference, check whether it is reference to a specific Type

			\param refType BNNamedTypeReference to check it against
			\return Whether it is a reference of this type
		*/
		bool IsReferenceOfType(BNNamedTypeReferenceClass refType);

		/*! If this Type is a NamedTypeReference, check whether it refers to a Struct Type

			\return Whether it refers to a struct type.
		*/
		bool IsStructReference() { return IsReferenceOfType(StructNamedTypeClass); }

		/*! If this Type is a NamedTypeReference, check whether it refers to an Enum Type

			\return Whether it refers to an Enum type.
		*/
		bool IsEnumReference() { return IsReferenceOfType(EnumNamedTypeClass); }

		/*! If this Type is a NamedTypeReference, check whether it refers to a Union Type

			\return Whether it refers to a union type.
		*/
		bool IsUnionReference() { return IsReferenceOfType(UnionNamedTypeClass); }

		/*! If this Type is a NamedTypeReference, check whether it refers to a Class Type

			\return Whether it refers to a class type.
		*/
		bool IsClassReference() { return IsReferenceOfType(ClassNamedTypeClass); }

		/*! If this Type is a NamedTypeReference, check whether it refers to a Typedef type

			\return Whether it refers to a typedef type.
		*/

		bool IsTypedefReference() { return IsReferenceOfType(TypedefNamedTypeClass); }

		/*! If this Type is a NamedTypeReference, check whether it refers to a Struct or Class Type

			\return Whether it refers to a struct or class type.
		*/
		bool IsStructOrClassReference()
		{
			return IsReferenceOfType(StructNamedTypeClass) || IsReferenceOfType(ClassNamedTypeClass);
		}

		/*! Check whether this type is a Void type.

			\return Whether this->GetClass() == VoidTypeClass
		*/
		bool IsVoid() const { return GetClass() == VoidTypeClass; }

		/*! Check whether this type is a Boolean type.

			\return Whether this->GetClass() == BoolTypeClass
		*/
		bool IsBool() const { return GetClass() == BoolTypeClass; }

		/*! Check whether this type is an Integer type.

			\return Whether this->GetClass() == IntegerTypeClass
		*/
		bool IsInteger() const { return GetClass() == IntegerTypeClass; }

		/*! Check whether this type is a Float type.

			\return Whether this->GetClass() == FloatTypeClass
		*/
		bool IsFloat() const { return GetClass() == FloatTypeClass; }

		/*! Check whether this type is a Structure type.

			\return Whether this->GetClass() == StructureTypeClass
		*/
		bool IsStructure() const { return GetClass() == StructureTypeClass; }

		/*! Check whether this type is an Enumeration type.

			\return Whether this->GetClass() == EnumerationTypeClass
		*/
		bool IsEnumeration() const { return GetClass() == EnumerationTypeClass; }

		/*! Check whether this type is a Pointer type.

			\return Whether this->GetClass() == PointerTypeClass
		*/
		bool IsPointer() const { return GetClass() == PointerTypeClass; }

		/*! Check whether this type is an Array type.

			\return Whether this->GetClass() == ArrayTypeClass
		*/
		bool IsArray() const { return GetClass() == ArrayTypeClass; }

		/*! Check whether this type is a Function type.

			\return Whether this->GetClass() == FunctionTypeClass
		*/
		bool IsFunction() const { return GetClass() == FunctionTypeClass; }

		/*! Check whether this type is a Variadic Arguments type.

			\return Whether this->GetClass() == VarArgsTypeClass
		*/
		bool IsVarArgs() const { return GetClass() == VarArgsTypeClass; }

		/*! Check whether this type is a Value type.

			\return Whether this->GetClass() == ValueTypeClass
		*/
		bool IsValue() const { return GetClass() == ValueTypeClass; }

		/*! Check whether this type is a Named Type Reference type.

			\return Whether this->GetClass() == NamedTypeReferenceClass
		*/
		bool IsNamedTypeRefer() const { return GetClass() == NamedTypeReferenceClass; }

		/*! Check whether this type is a Wide Char type.

			\return Whether this->GetClass() == WideCharTypeClass
		*/
		bool IsWideChar() const { return GetClass() == WideCharTypeClass; }

		Ref<Type> WithReplacedStructure(Structure* from, Structure* to);
		Ref<Type> WithReplacedEnumeration(Enumeration* from, Enumeration* to);
		Ref<Type> WithReplacedNamedTypeReference(NamedTypeReference* from, NamedTypeReference* to);

		bool AddTypeMemberTokens(BinaryView* data, std::vector<InstructionTextToken>& tokens, int64_t offset,
		    std::vector<std::string>& nameList, size_t size = 0, bool indirect = false);
		std::vector<TypeDefinitionLine> GetLines(Ref<BinaryView> data, const std::string& name,
			int lineWidth = 80, bool collapsed = false, BNTokenEscapingType escaping = NoTokenEscapingType);

		static std::string GetSizeSuffix(size_t size);
	};

	class EnumerationBuilder;
	class StructureBuilder;
	class NamedTypeReferenceBuilder;
	/*!
		\ingroup types
	*/
	class TypeBuilder
	{
		BNTypeBuilder* m_object;

	  public:
		TypeBuilder();
		TypeBuilder(BNTypeBuilder* type);
		TypeBuilder(const TypeBuilder& type);
		TypeBuilder(TypeBuilder&& type);
		TypeBuilder(Type* type);
		TypeBuilder& operator=(const TypeBuilder& type);
		TypeBuilder& operator=(TypeBuilder&& type);
		TypeBuilder& operator=(Type* type);

		Ref<Type> Finalize();

		BNTypeClass GetClass() const;
		uint64_t GetWidth() const;
		size_t GetAlignment() const;
		QualifiedName GetTypeName() const;
		Confidence<bool> IsSigned() const;
		Confidence<bool> IsConst() const;
		Confidence<bool> IsVolatile() const;
		bool IsSystemCall() const;
		void SetIntegerTypeDisplayType(BNIntegerDisplayType displayType);

		Confidence<Ref<Type>> GetChildType() const;
		Confidence<Ref<CallingConvention>> GetCallingConvention() const;
		std::vector<FunctionParameter> GetParameters() const;
		Confidence<bool> HasVariableArguments() const;
		Confidence<bool> CanReturn() const;
		Ref<Structure> GetStructure() const;
		Ref<Enumeration> GetEnumeration() const;
		Ref<NamedTypeReference> GetNamedTypeReference() const;
		Confidence<BNMemberScope> GetScope() const;
		TypeBuilder& SetNamedTypeReference(NamedTypeReference* ntr);
		TypeBuilder& SetScope(const Confidence<BNMemberScope>& scope);
		TypeBuilder& SetConst(const Confidence<bool>& cnst);
		TypeBuilder& SetVolatile(const Confidence<bool>& vltl);
		TypeBuilder& SetChildType(const Confidence<Ref<Type>>& child);
		TypeBuilder& SetSigned(const Confidence<bool>& vltl);
		TypeBuilder& SetTypeName(const QualifiedName& name);
		TypeBuilder& SetAlternateName(const std::string& name);
		TypeBuilder& SetSystemCall(bool sc, uint32_t n = 0);
		Confidence<int64_t> GetStackAdjustment() const;
		QualifiedName GetStructureName() const;

		uint64_t GetElementCount() const;
		uint64_t GetOffset() const;
		uint32_t GetSystemCallNumber() const;

		TypeBuilder& SetOffset(uint64_t offset);
		TypeBuilder& SetFunctionCanReturn(const Confidence<bool>& canReturn);
		TypeBuilder& SetParameters(const std::vector<FunctionParameter>& params);

		std::string GetString(Platform* platform = nullptr) const;
		std::string GetTypeAndName(const QualifiedName& name) const;
		std::string GetStringBeforeName(Platform* platform = nullptr) const;
		std::string GetStringAfterName(Platform* platform = nullptr) const;

		std::vector<InstructionTextToken> GetTokens(
		    Platform* platform = nullptr, uint8_t baseConfidence = BN_FULL_CONFIDENCE) const;
		std::vector<InstructionTextToken> GetTokensBeforeName(
		    Platform* platform = nullptr, uint8_t baseConfidence = BN_FULL_CONFIDENCE) const;
		std::vector<InstructionTextToken> GetTokensAfterName(
		    Platform* platform = nullptr, uint8_t baseConfidence = BN_FULL_CONFIDENCE) const;

		static TypeBuilder VoidType();
		static TypeBuilder BoolType();
		static TypeBuilder IntegerType(size_t width, const Confidence<bool>& sign, const std::string& altName = "");
		static TypeBuilder FloatType(size_t width, const std::string& typeName = "");
		static TypeBuilder WideCharType(size_t width, const std::string& typeName = "");
		static TypeBuilder StructureType(Structure* strct);
		static TypeBuilder StructureType(StructureBuilder* strct);
		static TypeBuilder NamedType(NamedTypeReference* ref, size_t width = 0, size_t align = 1,
		    const Confidence<bool>& cnst = Confidence<bool>(false, 0),
		    const Confidence<bool>& vltl = Confidence<bool>(false, 0));
		static TypeBuilder NamedType(NamedTypeReferenceBuilder* ref, size_t width = 0, size_t align = 1,
		    const Confidence<bool>& cnst = Confidence<bool>(false, 0),
		    const Confidence<bool>& vltl = Confidence<bool>(false, 0));
		static TypeBuilder NamedType(const QualifiedName& name, Type* type);
		static TypeBuilder NamedType(const std::string& id, const QualifiedName& name, Type* type);
		static TypeBuilder NamedType(BinaryView* view, const QualifiedName& name);
		static TypeBuilder EnumerationType(Architecture* arch, Enumeration* enm, size_t width = 0,
		    const Confidence<bool>& issigned = Confidence<bool>(false, 0));
		static TypeBuilder EnumerationType(Architecture* arch, EnumerationBuilder* enm, size_t width = 0,
		    const Confidence<bool>& issigned = Confidence<bool>(false, 0));
		static TypeBuilder PointerType(Architecture* arch, const Confidence<Ref<Type>>& type,
		    const Confidence<bool>& cnst = Confidence<bool>(false, 0),
		    const Confidence<bool>& vltl = Confidence<bool>(false, 0), BNReferenceType refType = PointerReferenceType);
		static TypeBuilder PointerType(size_t width, const Confidence<Ref<Type>>& type,
		    const Confidence<bool>& cnst = Confidence<bool>(false, 0),
		    const Confidence<bool>& vltl = Confidence<bool>(false, 0), BNReferenceType refType = PointerReferenceType);
		static TypeBuilder ArrayType(const Confidence<Ref<Type>>& type, uint64_t elem);
		static TypeBuilder FunctionType(const Confidence<Ref<Type>>& returnValue,
		    const Confidence<Ref<CallingConvention>>& callingConvention, const std::vector<FunctionParameter>& params,
		    const Confidence<bool>& varArg = Confidence<bool>(false, 0),
		    const Confidence<int64_t>& stackAdjust = Confidence<int64_t>(0, 0));
		static TypeBuilder FunctionType(const Confidence<Ref<Type>>& returnValue,
		    const Confidence<Ref<CallingConvention>>& callingConvention,
		    const std::vector<FunctionParameter>& params,
		    const Confidence<bool>& hasVariableArguments,
		    const Confidence<bool>& canReturn,
		    const Confidence<int64_t>& stackAdjust,
		    const std::map<uint32_t, Confidence<int32_t>>& regStackAdjust = std::map<uint32_t, Confidence<int32_t>>(),
		    const Confidence<std::vector<uint32_t>>& returnRegs = Confidence<std::vector<uint32_t>>(std::vector<uint32_t>(), 0),
		    BNNameType ft = NoNameType);

		bool IsReferenceOfType(BNNamedTypeReferenceClass refType);
		bool IsStructReference() { return IsReferenceOfType(StructNamedTypeClass); }
		bool IsEnumReference() { return IsReferenceOfType(EnumNamedTypeClass); }
		bool IsUnionReference() { return IsReferenceOfType(UnionNamedTypeClass); }
		bool IsClassReference() { return IsReferenceOfType(ClassNamedTypeClass); }
		bool IsTypedefReference() { return IsReferenceOfType(TypedefNamedTypeClass); }
		bool IsStructOrClassReference()
		{
			return IsReferenceOfType(StructNamedTypeClass) || IsReferenceOfType(ClassNamedTypeClass);
		}

		bool IsVoid() const { return GetClass() == VoidTypeClass; }
		bool IsBool() const { return GetClass() == BoolTypeClass; }
		bool IsInteger() const { return GetClass() == IntegerTypeClass; }
		bool IsFloat() const { return GetClass() == FloatTypeClass; }
		bool IsStructure() const { return GetClass() == StructureTypeClass; }
		bool IsEnumeration() const { return GetClass() == EnumerationTypeClass; }
		bool IsPointer() const { return GetClass() == PointerTypeClass; }
		bool IsArray() const { return GetClass() == ArrayTypeClass; }
		bool IsFunction() const { return GetClass() == FunctionTypeClass; }
		bool IsVarArgs() const { return GetClass() == VarArgsTypeClass; }
		bool IsValue() const { return GetClass() == ValueTypeClass; }
		bool IsNamedTypeRefer() const { return GetClass() == NamedTypeReferenceClass; }
		bool IsWideChar() const { return GetClass() == WideCharTypeClass; }
	};

	/*!
		\ingroup types
	*/
	class NamedTypeReference :
	    public CoreRefCountObject<BNNamedTypeReference, BNNewNamedTypeReference, BNFreeNamedTypeReference>
	{
	  public:
		NamedTypeReference(BNNamedTypeReference* nt);
		NamedTypeReference(BNNamedTypeReferenceClass cls = UnknownNamedTypeClass, const std::string& id = "",
		    const QualifiedName& name = QualifiedName());
		BNNamedTypeReferenceClass GetTypeReferenceClass() const;
		std::string GetTypeId() const;
		QualifiedName GetName() const;

		static Ref<NamedTypeReference> GenerateAutoTypeReference(
		    BNNamedTypeReferenceClass cls, const std::string& source, const QualifiedName& name);
		static Ref<NamedTypeReference> GenerateAutoDemangledTypeReference(
		    BNNamedTypeReferenceClass cls, const QualifiedName& name);
		static Ref<NamedTypeReference> GenerateAutoDebugTypeReference(
		    BNNamedTypeReferenceClass cls, const QualifiedName& name);
	};

	/*!
		\ingroup types
	*/
	class NamedTypeReferenceBuilder
	{
		BNNamedTypeReferenceBuilder* m_object;

	  public:
		NamedTypeReferenceBuilder(BNNamedTypeReferenceBuilder* nt);
		NamedTypeReferenceBuilder(BNNamedTypeReferenceClass cls = UnknownNamedTypeClass, const std::string& id = "",
		    const QualifiedName& name = QualifiedName());
		~NamedTypeReferenceBuilder();
		BNNamedTypeReferenceBuilder* GetObject() { return m_object; };
		BNNamedTypeReferenceClass GetTypeReferenceClass() const;
		std::string GetTypeId() const;
		QualifiedName GetName() const;

		void SetTypeReferenceClass(BNNamedTypeReferenceClass type);
		void SetTypeId(const std::string& id);
		void SetName(const QualifiedName& name);

		Ref<NamedTypeReference> Finalize();
	};

	/*!
		\ingroup types
	*/
	struct StructureMember
	{
		Ref<Type> type;
		std::string name;
		uint64_t offset;
		BNMemberAccess access;
		BNMemberScope scope;
	};

	/*! Structure is a class that wraps built structures and retrieves info about them.

		\see StructureBuilder is used for building structures
	 	\ingroup types
	*/
	class Structure : public CoreRefCountObject<BNStructure, BNNewStructureReference, BNFreeStructure>
	{
	  public:
		Structure(BNStructure* s);

		/*! Get a list of Structure members

			\return The list of structure members
		*/
		std::vector<StructureMember> GetMembers() const;

		/*! Get a structure member by name

			\param name Name of the member to retrieve
			\param result Reference to a StructureMember to copy the result to
			\return Whether a member was found
		*/
		bool GetMemberByName(const std::string& name, StructureMember& result) const;

		/*! Get a structure member at a certain offset

			\param offset Offset to check
			\param result Reference to a StructureMember to copy the result to
			\return Whether a member was found
		*/
		bool GetMemberAtOffset(int64_t offset, StructureMember& result) const;

		/*! Get a structure member and its index at a certain offset

			\param offset Offset to check
			\param result Reference to a StructureMember to copy the result to
			\param idx Reference to a size_t to copy the index to
			\return Whether a member was found
		*/
		bool GetMemberAtOffset(int64_t offset, StructureMember& result, size_t& idx) const;

		/*! Get the structure width in bytes

			\return The structure width in bytes
		*/
		uint64_t GetWidth() const;

		/*! Get the structure alignment

			\return The structure alignment
		*/
		size_t GetAlignment() const;

		/*! Whether the structure is packed

			\return Whether the structure is packed
		*/
		bool IsPacked() const;

		/*! Whether the structure is a union

			\return Whether the structure is a union
		*/
		bool IsUnion() const;

		/*! Get the structure type

			\return The structure type
		*/
		BNStructureVariant GetStructureType() const;

		Ref<Structure> WithReplacedStructure(Structure* from, Structure* to);
		Ref<Structure> WithReplacedEnumeration(Enumeration* from, Enumeration* to);
		Ref<Structure> WithReplacedNamedTypeReference(NamedTypeReference* from, NamedTypeReference* to);
	};

	/*! StructureBuilder is a convenience class used for building Structure Types.

	 	\b Example:
		\code{.cpp}
		StructureBuilder versionMinBuilder;
		versionMinBuilder.AddMember(Type::NamedType(bv, cmdTypeEnumQualName), "cmd");
		versionMinBuilder.AddMember(Type::IntegerType(4, false), "cmdsize");
		versionMinBuilder.AddMember(Type::IntegerType(4, false), "version");
		versionMinBuilder.AddMember(Type::IntegerType(4, false), "sdk");
		Ref<Structure> versionMinStruct = versionMinBuilder.Finalize();
		QualifiedName versionMinName = string("version_min");
		string versionMinTypeId = Type::GenerateAutoTypeId("macho", versionMinName);
		Ref<Type> versionMinType = Type::StructureType(versionMinStruct);
		QualifiedName versionMinQualName = bv->GetAnalysis()->DefineType(versionMinTypeId, versionMinName, versionMinType);
	 	\endcode

	 	\ingroup types
	*/
	class StructureBuilder
	{
		BNStructureBuilder* m_object;

	  public:
		StructureBuilder();
		StructureBuilder(BNStructureBuilder* s);
		StructureBuilder(BNStructureVariant type, bool packed = false);
		StructureBuilder(const StructureBuilder& s);
		StructureBuilder(StructureBuilder&& s);
		StructureBuilder(Structure* s);
		~StructureBuilder();
		StructureBuilder& operator=(const StructureBuilder& s);
		StructureBuilder& operator=(StructureBuilder&& s);
		StructureBuilder& operator=(Structure* s);
		BNStructureBuilder* GetObject() { return m_object; };

		/*! Complete the structure building process and return a Structure object

		    \return a built Structure object
		*/
		Ref<Structure> Finalize() const;

		/*! GetMembers returns a list of structure members

		    \return vector of StructureMember objects
		*/
		std::vector<StructureMember> GetMembers() const;

		/*! GetMemberByName retrieves a structure member by name

		    \param name Name of the member (field)
		    \param result Reference to a StructureMember object the field will be passed to
		    \return Whether a StructureMember was successfully retrieved
		*/
		bool GetMemberByName(const std::string& name, StructureMember& result) const;
		bool GetMemberAtOffset(int64_t offset, StructureMember& result) const;
		bool GetMemberAtOffset(int64_t offset, StructureMember& result, size_t& idx) const;
		uint64_t GetWidth() const;
		StructureBuilder& SetWidth(size_t width);
		size_t GetAlignment() const;
		StructureBuilder& SetAlignment(size_t align);
		bool IsPacked() const;
		StructureBuilder& SetPacked(bool packed);
		bool IsUnion() const;

		/*! Set the structure type

		    \param type One of: ClassStructureType, StructStructureType, UnionStructureType
		    \return reference to this StructureBuilder
		*/
		StructureBuilder& SetStructureType(BNStructureVariant type);

		/*! Get the Structure Type

		    \return A BNStructureVariant
		    \retval ClassStructureType If this structure represents a class
		    \retval StructStructureType If this structure represents a structure
		    \retval UnionStructureType If this structure represents a union
		*/
		BNStructureVariant GetStructureType() const;

		/*! AddMember adds a member (field) to a structure

		    \param type Type of the Field
		    \param name Name of the field
		    \param access Optional, One of NoAccess, PrivateAccess, ProtectedAccess, PublicAccess
		    \param scope Optional, One of NoScope, StaticScope, VirtualScope, ThunkScope, FriendScope
		    \return reference to the Structure Builder
		*/
		StructureBuilder& AddMember(const Confidence<Ref<Type>>& type, const std::string& name,
		    BNMemberAccess access = NoAccess, BNMemberScope scope = NoScope);

		/*! AddMemberAtOffset adds a member at a specific offset within the struct

		    \param type Type of the Field
		    \param name Name of the field
		    \param offset Offset to add the member within the struct
		    \param overwriteExisting Whether to overwrite an existing member at that offset, Optional, default true
		    \param access One of NoAccess, PrivateAccess, ProtectedAccess, PublicAccess
		    \param scope One of NoScope, StaticScope, VirtualScope, ThunkScope, FriendScope
		    \return Reference to the StructureBuilder
		*/
		StructureBuilder& AddMemberAtOffset(const Confidence<Ref<Type>>& type, const std::string& name, uint64_t offset,
		    bool overwriteExisting = true, BNMemberAccess access = NoAccess, BNMemberScope scope = NoScope);

		/*! RemoveMember removes a member at a specified index

		    \param idx Index to remove
		    \return Reference to the StructureBuilder
		*/
		StructureBuilder& RemoveMember(size_t idx);

		/*! ReplaceMember replaces a member at an index

		    \param idx Index of the StructureMember to be replaced
		    \param type Type of the new Member
		    \param name Name of the new Member
		    \param overwriteExisting Whether to overwrite the existing member, default true
		    \return Reference to the StructureBuilder
		*/
		StructureBuilder& ReplaceMember(
		    size_t idx, const Confidence<Ref<Type>>& type, const std::string& name, bool overwriteExisting = true);
	};

	/*!
		\ingroup types
	*/
	struct EnumerationMember
	{
		std::string name;
		uint64_t value;
		bool isDefault;
	};

	/*!
		\ingroup types
	*/
	class Enumeration : public CoreRefCountObject<BNEnumeration, BNNewEnumerationReference, BNFreeEnumeration>
	{
	  public:
		Enumeration(BNEnumeration* e);

		std::vector<EnumerationMember> GetMembers() const;
	};

	/*! EnumerationBuilder is a convenience class used for building Enumeration Types.

	 	\b Example:
	 	\code{.cpp}
		EnumerationBuilder segFlagsTypeBuilder;
		segFlagsTypeBuilder.AddMemberWithValue("SG_HIGHVM", 0x1);
		segFlagsTypeBuilder.AddMemberWithValue("SG_FVMLIB", 0x2);
		segFlagsTypeBuilder.AddMemberWithValue("SG_NORELOC", 0x4);
		segFlagsTypeBuilder.AddMemberWithValue("SG_PROTECTED_VERSION_1", 0x8);
		Ref<Enumeration> segFlagsTypeEnum = segFlagsTypeBuilder.Finalize();
	 	\endcode

	 	\ingroup types
	*/
	class EnumerationBuilder
	{
		BNEnumerationBuilder* m_object;

	  public:
		EnumerationBuilder();
		EnumerationBuilder(BNEnumerationBuilder* e);
		EnumerationBuilder(const EnumerationBuilder& e);
		EnumerationBuilder(EnumerationBuilder&& e);
		EnumerationBuilder(Enumeration* e);
		~EnumerationBuilder();
		BNEnumerationBuilder* GetObject() { return m_object; }
		EnumerationBuilder& operator=(const EnumerationBuilder& e);
		EnumerationBuilder& operator=(EnumerationBuilder&& e);
		EnumerationBuilder& operator=(Enumeration* e);

		/*! Finalize the building process and return the built Enumeration

			\return the Enumeration
		*/
		Ref<Enumeration> Finalize() const;

		/*! Get a list of members in this enum

			\return list of EnumerationMember
		*/
		std::vector<EnumerationMember> GetMembers() const;

		/*! Add a member to the enum.

			\note If there is already a member in the Enum, the value of newly added ones will be the value of the previously added one + 1

			\param name Name of the enum member
			\return A reference to this EnumerationBuilder
		*/
		EnumerationBuilder& AddMember(const std::string& name);

		/*! Add a member to the enum with a set value

			\param name Name of the enum member
			\param value Value of th enum member
			\return A reference to this EnumerationBuilder
		*/
		EnumerationBuilder& AddMemberWithValue(const std::string& name, uint64_t value);

		/*! Remove a member from the enum

			\param idx Index to remove
			\return  A reference to this EnumerationBuilder
		*/
		EnumerationBuilder& RemoveMember(size_t idx);

		/*! Replace a member at an index

			\param idx Index to replace
			\param name Name of the new member
			\param value Value of the new member
			\return  A reference to this EnumerationBuilder
		*/
		EnumerationBuilder& ReplaceMember(size_t idx, const std::string& name, uint64_t value);
	};

#if ((__cplusplus >= 201403L) || (_MSVC_LANG >= 201703L))
	template <class... Ts>
	struct overload : Ts...
	{
		using Ts::operator()...;
	};
	template <class... Ts>
	overload(Ts...) -> overload<Ts...>;
#endif

	/*!
		\ingroup workflow
	*/
	class AnalysisContext :
	    public CoreRefCountObject<BNAnalysisContext, BNNewAnalysisContextReference, BNFreeAnalysisContext>
	{
		std::unique_ptr<Json::CharReader> m_reader;
		Json::StreamWriterBuilder m_builder;

	  public:
		AnalysisContext(BNAnalysisContext* analysisContext);
		virtual ~AnalysisContext();

		/*! Get the Function for the current AnalysisContext

			\return The function for the current context
		*/
		Ref<Function> GetFunction();

		/*! Get the low level IL function for the current AnalysisContext

			\return The LowLevelILFunction for the current context
		*/
		Ref<LowLevelILFunction> GetLowLevelILFunction();

		/*! Get the medium level IL function for the current AnalysisContext

			\return The MediumLevelILFunction for the current context
		*/
		Ref<MediumLevelILFunction> GetMediumLevelILFunction();

		/*! Get the high level IL function for the current AnalysisContext

			\return The HighLevelILFunction for the current context
		*/
		Ref<HighLevelILFunction> GetHighLevelILFunction();

		/*! Set a new BasicBlock list for the current analysis context

			\param basicBlocks The new list of BasicBlocks
		*/
		void SetBasicBlockList(std::vector<Ref<BasicBlock>> basicBlocks);

		/*! Set new lifted IL for the current analysis context

			\param liftedIL The new lifted IL
		*/
		void SetLiftedILFunction(Ref<LowLevelILFunction> liftedIL);

		/*! Set the new Low Level IL for the current analysis context

			\param lowLevelIL the new Low Level IL
		*/
		void SetLowLevelILFunction(Ref<LowLevelILFunction> lowLevelIL);

		/*! Set the new Medium Level IL for the current analysis context

			\param mediumLevelIL the new Medium Level IL
		*/
		void SetMediumLevelILFunction(Ref<MediumLevelILFunction> mediumLevelIL);

		/*! Set the new High Level IL for the current analysis context

			\param highLevelIL the new High Level IL
		*/
		void SetHighLevelILFunction(Ref<HighLevelILFunction> highLevelIL);

		bool Inform(const std::string& request);

#if ((__cplusplus >= 201403L) || (_MSVC_LANG >= 201703L))
		template <typename... Args>
		bool Inform(Args... args)
		{
			// using T = std::variant<Args...>; // FIXME: remove type duplicates
			using T = std::variant<std::string, const char*, uint64_t, Ref<Architecture>>;
			std::vector<T> unpackedArgs {args...};
			Json::Value request(Json::arrayValue);
			for (auto& arg : unpackedArgs)
				std::visit(overload {[&](Ref<Architecture> arch) { request.append(Json::Value(arch->GetName())); },
				               [&](uint64_t val) { request.append(Json::Value(val)); },
				               [&](auto& val) {
					               request.append(Json::Value(std::forward<decltype(val)>(val)));
				               }},
				    arg);

			return Inform(Json::writeString(m_builder, request));
		}
#endif
	};

	/*!
		\ingroup workflow
	*/
	class Activity : public CoreRefCountObject<BNActivity, BNNewActivityReference, BNFreeActivity>
	{
	  protected:
		std::function<void(Ref<AnalysisContext> analysisContext)> m_action;

		static void Run(void* ctxt, BNAnalysisContext* analysisContext);

	  public:
		/*!

			\code{.cpp}
		    MyClass::MyActionMethod(Ref<AnalysisContext> ac);
		    ...
		 	// Create a clone of the default workflow named "core.function.myWorkflowName"
		    Ref<Workflow> wf = BinaryNinja::Workflow::Instance()->Clone("core.function.myWorkflowName");
		 	wf->RegisterActivity(new BinaryNinja::Activity(
				"core.function.myWorkflowName.resolveMethodCalls", &MyClass::MyActionMethod));
		 	\endcode

			\param name Name of the activity to register
			\param action Workflow action, a function taking a Ref<AnalysisContext> as an argument.
		*/
		Activity(const std::string& name, const std::function<void(Ref<AnalysisContext>)>& action);
		Activity(BNActivity* activity);
		virtual ~Activity();

		/*! Get the Activity name

			\return Activity name
		*/
		std::string GetName() const;
	};

	/*! A Binary Ninja Workflow is an abstraction of a computational binary analysis pipeline and it provides the extensibility
		mechanism needed for tailored binary analysis and decompilation. More specifically, a Workflow is a repository of activities along with a
		unique strategy to execute them. Binary Ninja provides two Workflows named ``core.module.defaultAnalysis`` and ``core.function.defaultAnalysis``
		which expose the core analysis.

		A Workflow starts in the unregistered state from either creating a new empty Workflow, or cloning an existing Workflow. While unregistered
		it's possible to add and remove activities, as well as change the execution strategy. In order to use the Workflow on a binary it must be
		registered. Once registered the Workflow is immutable and available for use.

	 	\ingroup workflow
	*/
	class Workflow : public CoreRefCountObject<BNWorkflow, BNNewWorkflowReference, BNFreeWorkflow>
	{
	  public:
		Workflow(const std::string& name = "");
		Workflow(BNWorkflow* workflow);
		virtual ~Workflow() {}

		/*! Get a list of all workflows

			\return A list of Workflows
		*/
		static std::vector<Ref<Workflow>> GetList();

		/*! Get an instance of a workflow by name. If it is already registered, this will return the registered Workflow.
			If not, it will create and return a new Workflow.

			\param name Workflow name
			\return The registered workflow.
		*/
		static Ref<Workflow> Instance(const std::string& name = "");
		/*! Register a workflow, making it immutable and available for use

			\param workflow The workflow to register
			\param description A JSON description of the Workflow
			\return true on success, false otherwise
		*/
		static bool RegisterWorkflow(Ref<Workflow> workflow, const std::string& description = "");

		/*! Clone a workflow, copying all Activities and the execution strategy

			\param name Name for the new Workflow
			\param activity If specified, perform the clone with `activity` as the root
			\return A new Workflow
		*/
		Ref<Workflow> Clone(const std::string& name, const std::string& activity = "");

		/*! Register an Activity with this Workflow

			\param activity The Activity to register
			\param description A JSON description of the Activity
			\return
		*/
		bool RegisterActivity(Ref<Activity> activity, const std::string& description = "");
		bool RegisterActivity(Ref<Activity> activity, std::initializer_list<const char*> initializer)
		{
			return RegisterActivity(activity, std::vector<std::string>(initializer.begin(), initializer.end()));
		}
		/*! Register an Activity with this Workflow

			\param activity The Activity to register
			\param subactivities The list of Activities to assign
			\param description A JSON description of the Activity
			\return
		*/
		bool RegisterActivity(
		    Ref<Activity> activity, const std::vector<std::string>& subactivities, const std::string& description = "");

		/*! Determine if an Activity exists in this Workflow

			\param activity The Activity name
			\return Whether the Activity exists in this workflow
		*/
		bool Contains(const std::string& activity);

		/*! Retrieve the configuration as an adjacency list in JSON for the Workflow,
			or if specified just for the given ``activity``.

			\param activity If specified, return the configuration for the ``activity``
			\return An adjacency list representation of the configuration in JSON
		*/
		std::string GetConfiguration(const std::string& activity = "");

		/*! Get the workflow name

			\return The workflow name
		*/
		std::string GetName() const;

		/*! Check whether the workflow is registered

			\return Whether the workflow is registered
		*/
		bool IsRegistered() const;

		/*! Get the amount of registered activities for this Workflow

			\return The amount of registered workflows
		*/
		size_t Size() const;

		/*! Retrieve an activity by name

			\param activity The Activity name
			\return The Activity object
		*/
		Ref<Activity> GetActivity(const std::string& activity);

		/*! Retrieve the list of activity roots for the Workflow, or if specified just for the given `activity`.

			\param activity If specified, return the roots for `activity`
			\return A list of root activity names.
		*/
		std::vector<std::string> GetActivityRoots(const std::string& activity = "");

		/*! Retrieve the list of all activities, or optionally a filtered list.

			\param activity If specified, return the direct children and optionally the descendants of the `activity` (includes `activity`)
			\param immediate whether to include only direct children of `activity` or all descendants
			\return A list of Activity names
		*/
		std::vector<std::string> GetSubactivities(const std::string& activity = "", bool immediate = true);

		/*! Assign the list of `activities` as the new set of children for the specified `activity`.

			\param activity The activity node to assign children
			\param subactivities the list of Activities to assign
			\return true on success, false otherwise
		*/
		bool AssignSubactivities(const std::string& activity, const std::vector<std::string>& subactivities = {});

		/*! Remove all activity nodes from this Workflow

			\return true on success, false otherwise
		*/
		bool Clear();

		/*! Insert an activity before the specified activity and at the same level.

			\param activity Name of the activity to insert the new one before
			\param newActivity Name of the new activity to be inserted
			\return true on success, false otherwise
		*/
		bool Insert(const std::string& activity, const std::string& newActivity);

		/*! Insert a list of activities before the specified activity and at the same level.

			\param activity Name of the activity to insert the new one before
			\param newActivity Name of the new activities to be inserted
			\return true on success, false otherwise
		*/
		bool Insert(const std::string& activity, const std::vector<std::string>& activities);

		/*! Remove an activity by name

			\param activity Name of the activity to remove
			\return true on success, false otherwise
		*/
		bool Remove(const std::string& activity);

		/*! Replace the activity name

			\param activity Name of the activity to replace
			\param newActivity Name of the new activity
			\return true on success, false otherwise
		*/
		bool Replace(const std::string& activity, const std::string& newActivity);

		/*! Generate a FlowGraph object for the current Workflow

			\param activity if specified, generate the Flowgraph using ``activity`` as the root
			\param sequential whether to generate a **Composite** or **Sequential** style graph
			\return FlowGraph on success
		*/
		Ref<FlowGraph> GetGraph(const std::string& activity = "", bool sequential = false);
		void ShowReport(const std::string& name);

		// bool Run(const std::string& activity, Ref<AnalysisContext> analysisContext);
	};

	class DisassemblySettings :
	    public CoreRefCountObject<BNDisassemblySettings, BNNewDisassemblySettingsReference, BNFreeDisassemblySettings>
	{
	  public:
		DisassemblySettings();
		DisassemblySettings(BNDisassemblySettings* settings);
		DisassemblySettings* Duplicate();

		bool IsOptionSet(BNDisassemblyOption option) const;
		void SetOption(BNDisassemblyOption option, bool state = true);

		size_t GetWidth() const;
		void SetWidth(size_t width);
		size_t GetMaximumSymbolWidth() const;
		void SetMaximumSymbolWidth(size_t width);
		size_t GetGutterWidth() const;
		void SetGutterWidth(size_t width);
	};

	/*!
		\ingroup basicblocks
	*/
	struct BasicBlockEdge
	{
		BNBranchType type;
		Ref<BasicBlock> target;
		bool backEdge;
		bool fallThrough;
	};

	/*!
		\ingroup basicblocks
	*/
	class BasicBlock : public CoreRefCountObject<BNBasicBlock, BNNewBasicBlockReference, BNFreeBasicBlock>
	{
	  public:
		BasicBlock(BNBasicBlock* block);

		/*! Basic block function

			\return The Function for this basic block
		*/
		Ref<Function> GetFunction() const;

		/*! Basic block architecture

			\return The Architecture for this Basic Block
		*/
		Ref<Architecture> GetArchitecture() const;

		/*! Starting address of the basic block

			\return Start address of the basic block
		*/
		uint64_t GetStart() const;

		/*! Ending address of the basic block

			\return Ending address of the basic block
		*/
		uint64_t GetEnd() const;

		/*! Length of the basic block

			\return Length of the basic block
		*/
		uint64_t GetLength() const;

		/*! Basic block index in list of blocks for the function

			\return Basic block index in list of blocks for the function
		*/
		size_t GetIndex() const;

		/*! List of basic block outgoing edges

			\return List of basic block outgoing edges
		*/
		std::vector<BasicBlockEdge> GetOutgoingEdges() const;

		/*! List of basic block incoming edges

			\return List of basic block incoming edges
		*/
		std::vector<BasicBlockEdge> GetIncomingEdges() const;

		/*! Whether basic block has undetermined outgoing edges

			\return Whether basic block has undetermined outgoing edges
		*/
		bool HasUndeterminedOutgoingEdges() const;

		/*! Whether basic block can return or is tagged as 'No Return'

			\return Whether basic block can return or is tagged as 'No Return'
		*/
		bool CanExit() const;

		/*! Sets whether basic block can return or is tagged as 'No Return'

			\param value Sets whether basic block can return or is tagged as 'No Return'
		*/
		void SetCanExit(bool value);

		/*! List of dominators for this basic block

			\param post Whether to get post dominators (default: false)
			\return Set of BasicBlock dominators
		*/
		std::set<Ref<BasicBlock>> GetDominators(bool post = false) const;

		/*! List of dominators for this basic block

			\param post Whether to get post dominators (default: false)
			\return Set of BasicBlock dominators
		*/
		std::set<Ref<BasicBlock>> GetStrictDominators(bool post = false) const;

		/*! Get the immediate dominator of this basic block

			\param post Whether to get the immediate post dominator
			\return Immediate dominator basic block
		*/
		Ref<BasicBlock> GetImmediateDominator(bool post = false) const;

		/*! List of child blocks in the dominator tree for this basic block

			\param post Whether to get the post dominator tree children
			\return Set of Tree children
		*/
		std::set<Ref<BasicBlock>> GetDominatorTreeChildren(bool post = false) const;

		/*! Get the dominance frontier for this basic block

			\param post Whether to get the post dominance frontier
			\return Post dominance frontier for this basic block
		*/
		std::set<Ref<BasicBlock>> GetDominanceFrontier(bool post = false) const;
		static std::set<Ref<BasicBlock>> GetIteratedDominanceFrontier(const std::set<Ref<BasicBlock>>& blocks);

		void MarkRecentUse();

		/*! List of automatic annotations for the start of this block

			\return List of automatic annotations for the start of this block
		*/
		std::vector<std::vector<InstructionTextToken>> GetAnnotations();

		/*! property which returns a list of DisassemblyTextLine objects for the current basic block.

			\param settings Disassembly settings to use when fetching the text
			\return Disassembly text
		*/
		std::vector<DisassemblyTextLine> GetDisassemblyText(DisassemblySettings* settings);

		/*! Get the current highlight color for the Basic Block

			\return The current highlight color for the Basic Block
		*/
		BNHighlightColor GetBasicBlockHighlight();

		/*! Set the analysis basic block highlight color

			\param color Highlight Color
		*/
		void SetAutoBasicBlockHighlight(BNHighlightColor color);

		/*! Set the analysis basic block highlight color

			\param color Highlight Color
			\param alpha Transparency for the color
		*/
		void SetAutoBasicBlockHighlight(BNHighlightStandardColor color, uint8_t alpha = 255);

		/*! Set the analysis basic block highlight color

			\param color Highlight Color
			\param mixColor Highlight Color to mix with `color`
			\param mix Mix point
			\param alpha Transparency of the colors
		*/
		void SetAutoBasicBlockHighlight(
		    BNHighlightStandardColor color, BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha = 255);

		/*! Set the analysis basic block highlight color

			\param r Red value, 0-255
			\param g Green value, 0-255
			\param b Blue value, 0-255
			\param alpha Transparency of the color
		*/
		void SetAutoBasicBlockHighlight(uint8_t r, uint8_t g, uint8_t b, uint8_t alpha = 255);

		/*! Set the basic block highlight color

			\param color Highlight color
		*/
		void SetUserBasicBlockHighlight(BNHighlightColor color);

		/*! Set the basic block highlight color

			\param color Highlight color
			\param alpha Transparency of the color
		*/
		void SetUserBasicBlockHighlight(BNHighlightStandardColor color, uint8_t alpha = 255);

		/*! Set the basic block highlight color

			\param color Highlight Color
			\param mixColor Highlight Color to mix with `color`
			\param mix Mix point
			\param alpha Transparency of the colors
		*/
		void SetUserBasicBlockHighlight(
		    BNHighlightStandardColor color, BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha = 255);

		/*! Set the basic block highlight color

			\param r Red value, 0-255
			\param g Green value, 0-255
			\param b Blue value, 0-255
			\param alpha Transparency of the color
		*/
		void SetUserBasicBlockHighlight(uint8_t r, uint8_t g, uint8_t b, uint8_t alpha = 255);

		static bool IsBackEdge(BasicBlock* source, BasicBlock* target);

		/*! Whether the basic block contains IL

			\return Whether the basic block contains IL
		*/
		bool IsILBlock() const;

		/*! Whether the basic block contains Medium Level IL

			\return Whether the basic block contains Medium Level IL
		*/
		bool IsLowLevelILBlock() const;

		/*! Whether the basic block contains High Level IL

			\return Whether the basic block contains High Level IL
		*/
		bool IsMediumLevelILBlock() const;

		/*! Get the Low Level IL Function for this basic block

			\return Get the Low Level IL Function for this basic block
		*/
		Ref<LowLevelILFunction> GetLowLevelILFunction() const;

		/*! Get the Medium Level IL Function for this basic block

			\return Get the Medium Level IL Function for this basic block
		*/
		Ref<MediumLevelILFunction> GetMediumLevelILFunction() const;

		/*! Get the High Level IL Function for this basic block

			\return Get the High Level IL Function for this basic block
		*/
		Ref<HighLevelILFunction> GetHighLevelILFunction() const;

		bool GetInstructionContainingAddress(uint64_t addr, uint64_t* start);

		/*! Basic block source block

			\return Basic block source block
		*/
		Ref<BasicBlock> GetSourceBlock() const;
	};

	/*!
		\ingroup function
	*/
	struct VariableNameAndType
	{
		Variable var;
		Confidence<Ref<Type>> type;
		std::string name;
		bool autoDefined;

		bool operator==(const VariableNameAndType& a)
		{
			return (var == a.var) && (type == a.type) && (name == a.name) && (autoDefined == a.autoDefined);
		}
		bool operator!=(const VariableNameAndType& a)
		{
			return !(*this == a);
		}
	};

	/*!
		\ingroup function
	*/
	struct StackVariableReference
	{
		uint32_t sourceOperand;
		Confidence<Ref<Type>> type;
		std::string name;
		Variable var;
		int64_t referencedOffset;
		size_t size;
	};

	/*!
		\ingroup function
	*/
	struct IndirectBranchInfo
	{
		Ref<Architecture> sourceArch;
		uint64_t sourceAddr;
		Ref<Architecture> destArch;
		uint64_t destAddr;
		bool autoDefined;
	};

	/*!
		\ingroup function
	*/
	struct ArchAndAddr
	{
		Ref<Architecture> arch;
		uint64_t address;

		ArchAndAddr& operator=(const ArchAndAddr& a)
		{
			arch = a.arch;
			address = a.address;
			return *this;
		}
		bool operator==(const ArchAndAddr& a) const { return (arch == a.arch) && (address == a.address); }
		bool operator<(const ArchAndAddr& a) const
		{
			if (arch < a.arch)
				return true;
			if (arch > a.arch)
				return false;
			return address < a.address;
		}
		ArchAndAddr() : arch(nullptr), address(0) {}
		ArchAndAddr(Architecture* a, uint64_t addr) : arch(a), address(addr) {}
	};

	/*!
		\ingroup function
	*/
	struct LookupTableEntry
	{
		std::vector<int64_t> fromValues;
		int64_t toValue;
	};

	/*!
		\ingroup function
	*/
	struct RegisterValue
	{
		BNRegisterValueType state;
		int64_t value;
		int64_t offset;

		RegisterValue();

		bool IsConstant() const;

		static RegisterValue FromAPIObject(const BNRegisterValue& value);
		BNRegisterValue ToAPIObject();
	};

	/*!
		\ingroup function
	*/
	struct PossibleValueSet
	{
		BNRegisterValueType state;
		int64_t value;
		int64_t offset;
		std::vector<BNValueRange> ranges;
		std::set<int64_t> valueSet;
		std::vector<LookupTableEntry> table;
		size_t count;

		static PossibleValueSet FromAPIObject(BNPossibleValueSet& value);
		BNPossibleValueSet ToAPIObject();
	};

	class FlowGraph;
	class Component;
	struct SSAVariable;

	/*!
		\ingroup function
	*/
	class Function : public CoreRefCountObject<BNFunction, BNNewFunctionReference, BNFreeFunction>
	{
		int m_advancedAnalysisRequests;

	  public:
		Function(BNFunction* func);
		virtual ~Function();

		/*! Get the BinaryView this Function is defined in

			\return a BinaryView reference
		*/
		Ref<BinaryView> GetView() const;

		/*! Get the architecture this function was defined with

			\return an Architecture reference
		*/
		Ref<Architecture> GetArchitecture() const;

		/*! Get the platform this function was defined with

			\return a Platform reference
		*/
		Ref<Platform> GetPlatform() const;

		/*! Get the starting virtual address of this function

			\return the start address
		*/
		uint64_t GetStart() const;

		/*! Get the Symbol for this function

			\return a Symbol reference
		*/
		Ref<Symbol> GetSymbol() const;

		/*! Whether this function was automatically discovered by analysis

			\return Whether the function was automatically discovered
		*/
		bool WasAutomaticallyDiscovered() const;

		/*! Whether this function has user annotations

			\return Whether this function has user annotations
		*/
		bool HasUserAnnotations() const;

		/*! Whether this function can return

			\return Whether this function can return
		*/
		Confidence<bool> CanReturn() const;

		/*! Whether this function has an explicitly defined type

			\return Whether this function has an explicitly defined type
		*/
		bool HasExplicitlyDefinedType() const;

		/*! Whether this function needs update

			\return Whether this function needs update
		*/
		bool NeedsUpdate() const;
		std::vector<Ref<Component>> GetParentComponents() const;

		/*! Get a list of Basic Blocks for this function

			\return a list of BasicBlock references for this function
		*/
		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;

		/*! Get the basic block an address is located in

			\param arch Architecture for the basic block
			\param addr Address to check
			\return
		*/
		Ref<BasicBlock> GetBasicBlockAtAddress(Architecture* arch, uint64_t addr) const;

		/*! Mark this function as recently used
		*/
		void MarkRecentUse();

		/*! Get the function comment

			\return The function comment
		*/
		std::string GetComment() const;

		/*! Get a comment located at an address

		 	\return The comment at an address
		*/
		std::string GetCommentForAddress(uint64_t addr) const;

		/*! Get a list of addresses with comments

			\return A list of virtual addresses with comments
		*/
		std::vector<uint64_t> GetCommentedAddresses() const;

		/*! Set the comment for the function

			\param comment The new function comment
		*/
		void SetComment(const std::string& comment);

		/*! Set the comment at an address

			\param addr Address for the comment
			\param comment Text of the comment
		*/
		void SetCommentForAddress(uint64_t addr, const std::string& comment);

		/*! Get a list of callsites for this function

			\return a list of ReferenceSource
		*/
		std::vector<ReferenceSource> GetCallSites() const;

		/*! Places a user-defined cross-reference from the instruction at
			the given address and architecture to the specified target address. 
		 
		 	If the specified source instruction is not contained within this function, no action is performed.
			To remove the reference, use `RemoveUserCodeReference`.

			\param fromArch Architecture of the source instruction
			\param fromAddr Virtual address of the source instruction
			\param toAddr Virtual address of the xref's destination.
		*/
		void AddUserCodeReference(Architecture* fromArch, uint64_t fromAddr, uint64_t toAddr);

		/*! Removes a user-defined cross-reference.

		    If the given address is not contained within this function, or if there is no such user-defined 
		    cross-reference, no action is performed.

			\param fromArch Architecture of the source instruction
			\param fromAddr Virtual address of the source instruction
			\param toAddr Virtual address of the xref's destination.
		*/
		void RemoveUserCodeReference(Architecture* fromArch, uint64_t fromAddr, uint64_t toAddr);

		/*! Places a user-defined type cross-reference from the instruction at
				the given address and architecture to the specified type. 
		 
		 	If the specified source instruction is not contained within this function, no action is performed.
			To remove the reference, use `RemoveUserTypeReference`.

		    \param fromArch Architecture of the source instruction
		    \param fromAddr Virtual address of the source instruction
			\param name Name of the referenced type
		*/
		void AddUserTypeReference(Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name);

		/*! Removes a user-defined type cross-reference.

			If the given address is not contained within this function, or if there is no
			such user-defined cross-reference, no action is performed.

			\param fromArch Architecture of the source instruction
			\param fromAddr Virtual address of the source instruction
			\param name Name of the referenced type
		*/
		void RemoveUserTypeReference(Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name);

		/*! Places a user-defined type field cross-reference from the
			instruction at the given address and architecture to the specified type. 
		 
			If the specified source instruction is not contained within this function, no action is performed.
			To remove the reference, use :func:`remove_user_type_field_ref`.

			\param fromArch Architecture of the source instruction
			\param fromAddr Virtual address of the source instruction
			\param name Name of the referenced type
			\param offset Offset of the field, relative to the type
			\param size (Optional) size of the access
		*/
		void AddUserTypeFieldReference(
		    Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name, uint64_t offset, size_t size = 0);

		/*! Removes a user-defined type field cross-reference.

		 	If the given address is not contained within this function, or if there is no
			such user-defined cross-reference, no action is performed.

			\param fromArch Architecture of the source instruction
			\param fromAddr Virtual address of the source instruction
			\param name Name of the referenced type
			\param offset Offset of the field, relative to the type
			\param size (Optional) size of the access
		*/
		void RemoveUserTypeFieldReference(
		    Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name, uint64_t offset, size_t size = 0);

		/*! Get the LLIL for this function

			\return a LowLevelILFunction reference
		*/
		Ref<LowLevelILFunction> GetLowLevelIL() const;

		/*! Get the LLIL for this function if it is available

			\return a LowLevelILFunction reference
		*/
		Ref<LowLevelILFunction> GetLowLevelILIfAvailable() const;

		/*! Get the Low Level IL Instruction start for an instruction at an address

			\param arch Architecture for the instruction
			\param addr Address of the instruction
			\return Start address of the instruction
		*/
		size_t GetLowLevelILForInstruction(Architecture* arch, uint64_t addr);
		std::set<size_t> GetLowLevelILInstructionsForAddress(Architecture* arch, uint64_t addr);
		std::vector<size_t> GetLowLevelILExitsForInstruction(Architecture* arch, uint64_t addr);
		RegisterValue GetRegisterValueAtInstruction(Architecture* arch, uint64_t addr, uint32_t reg);
		RegisterValue GetRegisterValueAfterInstruction(Architecture* arch, uint64_t addr, uint32_t reg);
		RegisterValue GetStackContentsAtInstruction(Architecture* arch, uint64_t addr, int64_t offset, size_t size);
		RegisterValue GetStackContentsAfterInstruction(Architecture* arch, uint64_t addr, int64_t offset, size_t size);
		RegisterValue GetParameterValueAtInstruction(Architecture* arch, uint64_t addr, Type* functionType, size_t i);
		RegisterValue GetParameterValueAtLowLevelILInstruction(size_t instr, Type* functionType, size_t i);
		std::vector<uint32_t> GetRegistersReadByInstruction(Architecture* arch, uint64_t addr);
		std::vector<uint32_t> GetRegistersWrittenByInstruction(Architecture* arch, uint64_t addr);
		std::vector<StackVariableReference> GetStackVariablesReferencedByInstruction(Architecture* arch, uint64_t addr);
		std::vector<StackVariableReference> GetStackVariablesReferencedByInstructionIfAvailable(
			Architecture* arch, uint64_t addr);
		std::vector<BNConstantReference> GetConstantsReferencedByInstruction(Architecture* arch, uint64_t addr);
		std::vector<BNConstantReference> GetConstantsReferencedByInstructionIfAvailable(
			Architecture* arch, uint64_t addr);

		std::vector<ILReferenceSource> GetMediumLevelILVariableReferences(const Variable& var);
		std::vector<VariableReferenceSource> GetMediumLevelILVariableReferencesFrom(Architecture* arch, uint64_t addr);
		std::vector<VariableReferenceSource> GetMediumLevelILVariableReferencesInRange(
		    Architecture* arch, uint64_t addr, uint64_t len);
		std::vector<ILReferenceSource> GetMediumLevelILVariableReferencesIfAvailable(const Variable& var);
		std::vector<VariableReferenceSource> GetMediumLevelILVariableReferencesFromIfAvailable(
		    Architecture* arch, uint64_t addr);
		std::vector<VariableReferenceSource> GetMediumLevelILVariableReferencesInRangeIfAvailable(
		    Architecture* arch, uint64_t addr, uint64_t len);

		std::vector<ILReferenceSource> GetHighLevelILVariableReferences(const Variable& var);
		std::vector<VariableReferenceSource> GetHighLevelILVariableReferencesFrom(Architecture* arch, uint64_t addr);
		std::vector<VariableReferenceSource> GetHighLevelILVariableReferencesInRange(
		    Architecture* arch, uint64_t addr, uint64_t len);
		std::vector<ILReferenceSource> GetHighLevelILVariableReferencesIfAvailable(const Variable& var);
		std::vector<VariableReferenceSource> GetHighLevelILVariableReferencesFromIfAvailable(
		    Architecture* arch, uint64_t addr);
		std::vector<VariableReferenceSource> GetHighLevelILVariableReferencesInRangeIfAvailable(
		    Architecture* arch, uint64_t addr, uint64_t len);

		/*! Retrieves a LowLevelILFunction used to represent lifted IL.

			\return LowLevelILFunction used to represent lifted IL.
		*/
		Ref<LowLevelILFunction> GetLiftedIL() const;

		/*! Retrieves a LowLevelILFunction used to represent lifted IL, or None if not loaded.

			\return LowLevelILFunction used to represent lifted IL, or None if not loaded.
		*/
		Ref<LowLevelILFunction> GetLiftedILIfAvailable() const;
		size_t GetLiftedILForInstruction(Architecture* arch, uint64_t addr);
		std::set<size_t> GetLiftedILInstructionsForAddress(Architecture* arch, uint64_t addr);
		std::set<size_t> GetLiftedILFlagUsesForDefinition(size_t i, uint32_t flag);
		std::set<size_t> GetLiftedILFlagDefinitionsForUse(size_t i, uint32_t flag);
		std::set<uint32_t> GetFlagsReadByLiftedILInstruction(size_t i);
		std::set<uint32_t> GetFlagsWrittenByLiftedILInstruction(size_t i);

		/*! Get the MLIL for this Function.

			\return The MLIL for this Function.
		*/
		Ref<MediumLevelILFunction> GetMediumLevelIL() const;

		/*! Get the MLIL for this Function if it's available.

			\return The MLIL for this Function if it's available.
		*/
		Ref<MediumLevelILFunction> GetMediumLevelILIfAvailable() const;

		/*! Get the Mapped MLIL for this Function.

			\return The Mapped MLIL for this Function.
		*/
		Ref<MediumLevelILFunction> GetMappedMediumLevelIL() const;

		/*! Get the Mapped MLIL for this Function if it's available.

			\return The Mapped MLIL for this Function if it's available.
		*/
		Ref<MediumLevelILFunction> GetMappedMediumLevelILIfAvailable() const;

		/*! Get the HLIL for this Function.

			\return The HLIL for this Function.
		*/
		Ref<HighLevelILFunction> GetHighLevelIL() const;

		/*! Get the HLIL for this Function if it's available.

			\return The HLIL for this Function if it's available.
		*/
		Ref<HighLevelILFunction> GetHighLevelILIfAvailable() const;
		Ref<LanguageRepresentationFunction> GetLanguageRepresentation() const;
		Ref<LanguageRepresentationFunction> GetLanguageRepresentationIfAvailable() const;

		Ref<Type> GetType() const;
		Confidence<Ref<Type>> GetReturnType() const;
		Confidence<std::vector<uint32_t>> GetReturnRegisters() const;
		Confidence<Ref<CallingConvention>> GetCallingConvention() const;
		Confidence<std::vector<Variable>> GetParameterVariables() const;
		Confidence<bool> HasVariableArguments() const;
		Confidence<int64_t> GetStackAdjustment() const;
		std::map<uint32_t, Confidence<int32_t>> GetRegisterStackAdjustments() const;
		Confidence<std::set<uint32_t>> GetClobberedRegisters() const;

		void SetAutoType(Type* type);
		void SetAutoReturnType(const Confidence<Ref<Type>>& type);
		void SetAutoReturnRegisters(const Confidence<std::vector<uint32_t>>& returnRegs);
		void SetAutoCallingConvention(const Confidence<Ref<CallingConvention>>& convention);
		void SetAutoParameterVariables(const Confidence<std::vector<Variable>>& vars);
		void SetAutoHasVariableArguments(const Confidence<bool>& varArgs);
		void SetAutoCanReturn(const Confidence<bool>& returns);
		void SetAutoStackAdjustment(const Confidence<int64_t>& stackAdjust);
		void SetAutoRegisterStackAdjustments(const std::map<uint32_t, Confidence<int32_t>>& regStackAdjust);
		void SetAutoClobberedRegisters(const Confidence<std::set<uint32_t>>& clobbered);

		void SetUserType(Type* type);
		void SetReturnType(const Confidence<Ref<Type>>& type);
		void SetReturnRegisters(const Confidence<std::vector<uint32_t>>& returnRegs);
		void SetCallingConvention(const Confidence<Ref<CallingConvention>>& convention);
		void SetParameterVariables(const Confidence<std::vector<Variable>>& vars);
		void SetHasVariableArguments(const Confidence<bool>& varArgs);
		void SetCanReturn(const Confidence<bool>& returns);
		void SetStackAdjustment(const Confidence<int64_t>& stackAdjust);
		void SetRegisterStackAdjustments(const std::map<uint32_t, Confidence<int32_t>>& regStackAdjust);
		void SetClobberedRegisters(const Confidence<std::set<uint32_t>>& clobbered);

		void ApplyImportedTypes(Symbol* sym, Ref<Type> type = nullptr);
		void ApplyAutoDiscoveredType(Type* type);

		Ref<FlowGraph> CreateFunctionGraph(BNFunctionGraphType type, DisassemblySettings* settings = nullptr);

		std::map<int64_t, std::vector<VariableNameAndType>> GetStackLayout();
		void CreateAutoStackVariable(int64_t offset, const Confidence<Ref<Type>>& type, const std::string& name);
		void CreateUserStackVariable(int64_t offset, const Confidence<Ref<Type>>& type, const std::string& name);
		void DeleteAutoStackVariable(int64_t offset);
		void DeleteUserStackVariable(int64_t offset);
		bool GetStackVariableAtFrameOffset(Architecture* arch, uint64_t addr, int64_t offset, VariableNameAndType& var);

		/*! List of Function Variables

			\return List of Function Variables
		*/
		std::map<Variable, VariableNameAndType> GetVariables();
		std::set<Variable> GetMediumLevelILVariables();
		std::set<Variable> GetMediumLevelILAliasedVariables();
		std::set<SSAVariable> GetMediumLevelILSSAVariables();
		std::set<Variable> GetHighLevelILVariables();
		std::set<Variable> GetHighLevelILAliasedVariables();
		std::set<SSAVariable> GetHighLevelILSSAVariables();

		std::set<Variable> GetMediumLevelILVariablesIfAvailable();
		std::set<Variable> GetMediumLevelILAliasedVariablesIfAvailable();
		std::set<SSAVariable> GetMediumLevelILSSAVariablesIfAvailable();
		std::set<Variable> GetHighLevelILVariablesIfAvailable();
		std::set<Variable> GetHighLevelILAliasedVariablesIfAvailable();
		std::set<SSAVariable> GetHighLevelILSSAVariablesIfAvailable();

		void CreateAutoVariable(const Variable& var, const Confidence<Ref<Type>>& type, const std::string& name,
		    bool ignoreDisjointUses = false);
		void CreateUserVariable(const Variable& var, const Confidence<Ref<Type>>& type, const std::string& name,
		    bool ignoreDisjointUses = false);
		void DeleteAutoVariable(const Variable& var);
		void DeleteUserVariable(const Variable& var);
		bool IsVariableUserDefinded(const Variable& var);
		Confidence<Ref<Type>> GetVariableType(const Variable& var);
		std::string GetVariableName(const Variable& var);
		std::string GetVariableNameOrDefault(const Variable& var);
		std::string GetLastSeenVariableNameOrDefault(const Variable& var);

		void SetAutoIndirectBranches(
		    Architecture* sourceArch, uint64_t source, const std::vector<ArchAndAddr>& branches);
		void SetUserIndirectBranches(
		    Architecture* sourceArch, uint64_t source, const std::vector<ArchAndAddr>& branches);

		std::vector<IndirectBranchInfo> GetIndirectBranches();
		std::vector<IndirectBranchInfo> GetIndirectBranchesAt(Architecture* arch, uint64_t addr);

		std::vector<uint64_t> GetUnresolvedIndirectBranches();
		bool HasUnresolvedIndirectBranches();

		void SetAutoCallTypeAdjustment(Architecture* arch, uint64_t addr, const Confidence<Ref<Type>>& adjust);
		void SetAutoCallStackAdjustment(Architecture* arch, uint64_t addr, const Confidence<int64_t>& adjust);
		void SetAutoCallRegisterStackAdjustment(
		    Architecture* arch, uint64_t addr, const std::map<uint32_t, Confidence<int32_t>>& adjust);
		void SetAutoCallRegisterStackAdjustment(
		    Architecture* arch, uint64_t addr, uint32_t regStack, const Confidence<int32_t>& adjust);
		void SetUserCallTypeAdjustment(Architecture* arch, uint64_t addr, const Confidence<Ref<Type>>& adjust);
		void SetUserCallStackAdjustment(Architecture* arch, uint64_t addr, const Confidence<int64_t>& adjust);
		void SetUserCallRegisterStackAdjustment(
		    Architecture* arch, uint64_t addr, const std::map<uint32_t, Confidence<int32_t>>& adjust);
		void SetUserCallRegisterStackAdjustment(
		    Architecture* arch, uint64_t addr, uint32_t regStack, const Confidence<int32_t>& adjust);

		Confidence<Ref<Type>> GetCallTypeAdjustment(Architecture* arch, uint64_t addr);
		Confidence<int64_t> GetCallStackAdjustment(Architecture* arch, uint64_t addr);
		std::map<uint32_t, Confidence<int32_t>> GetCallRegisterStackAdjustment(Architecture* arch, uint64_t addr);
		Confidence<int32_t> GetCallRegisterStackAdjustment(Architecture* arch, uint64_t addr, uint32_t regStack);
		bool IsCallInstruction(Architecture* arch, uint64_t addr);

		std::vector<std::vector<InstructionTextToken>> GetBlockAnnotations(Architecture* arch, uint64_t addr);

		BNIntegerDisplayType GetIntegerConstantDisplayType(
		    Architecture* arch, uint64_t instrAddr, uint64_t value, size_t operand);
		void SetIntegerConstantDisplayType(
		    Architecture* arch, uint64_t instrAddr, uint64_t value, size_t operand, BNIntegerDisplayType type);

		BNHighlightColor GetInstructionHighlight(Architecture* arch, uint64_t addr);
		void SetAutoInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightColor color);
		void SetAutoInstructionHighlight(
		    Architecture* arch, uint64_t addr, BNHighlightStandardColor color, uint8_t alpha = 255);
		void SetAutoInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightStandardColor color,
		    BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha = 255);
		void SetAutoInstructionHighlight(
		    Architecture* arch, uint64_t addr, uint8_t r, uint8_t g, uint8_t b, uint8_t alpha = 255);
		void SetUserInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightColor color);
		void SetUserInstructionHighlight(
		    Architecture* arch, uint64_t addr, BNHighlightStandardColor color, uint8_t alpha = 255);
		void SetUserInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightStandardColor color,
		    BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha = 255);
		void SetUserInstructionHighlight(
		    Architecture* arch, uint64_t addr, uint8_t r, uint8_t g, uint8_t b, uint8_t alpha = 255);

		std::vector<TagReference> GetAllTagReferences();
		std::vector<TagReference> GetTagReferencesOfType(Ref<TagType> tagType);

		std::vector<TagReference> GetAddressTagReferences();
		std::vector<TagReference> GetAutoAddressTagReferences();
		std::vector<TagReference> GetUserAddressTagReferences();
		std::vector<Ref<Tag>> GetAddressTags(Architecture* arch, uint64_t addr);
		std::vector<Ref<Tag>> GetAutoAddressTags(Architecture* arch, uint64_t addr);
		std::vector<Ref<Tag>> GetUserAddressTags(Architecture* arch, uint64_t addr);
		std::vector<Ref<Tag>> GetAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType);
		std::vector<Ref<Tag>> GetAutoAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType);
		std::vector<Ref<Tag>> GetUserAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType);
		std::vector<TagReference> GetAddressTagsInRange(Architecture* arch, uint64_t start, uint64_t end);
		std::vector<TagReference> GetAutoAddressTagsInRange(Architecture* arch, uint64_t start, uint64_t end);
		std::vector<TagReference> GetUserAddressTagsInRange(Architecture* arch, uint64_t start, uint64_t end);
		void AddAutoAddressTag(Architecture* arch, uint64_t addr, Ref<Tag> tag);
		void RemoveAutoAddressTag(Architecture* arch, uint64_t addr, Ref<Tag> tag);
		void RemoveAutoAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType);
		void AddUserAddressTag(Architecture* arch, uint64_t addr, Ref<Tag> tag);
		void RemoveUserAddressTag(Architecture* arch, uint64_t addr, Ref<Tag> tag);
		void RemoveUserAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType);

		std::vector<TagReference> GetFunctionTagReferences();
		std::vector<TagReference> GetAutoFunctionTagReferences();
		std::vector<TagReference> GetUserFunctionTagReferences();
		std::vector<Ref<Tag>> GetFunctionTags();
		std::vector<Ref<Tag>> GetAutoFunctionTags();
		std::vector<Ref<Tag>> GetUserFunctionTags();
		std::vector<Ref<Tag>> GetFunctionTagsOfType(Ref<TagType> tagType);
		std::vector<Ref<Tag>> GetAutoFunctionTagsOfType(Ref<TagType> tagType);
		std::vector<Ref<Tag>> GetUserFunctionTagsOfType(Ref<TagType> tagType);
		void AddAutoFunctionTag(Ref<Tag> tag);
		void RemoveAutoFunctionTag(Ref<Tag> tag);
		void RemoveAutoFunctionTagsOfType(Ref<TagType> tagType);
		void AddUserFunctionTag(Ref<Tag> tag);
		void RemoveUserFunctionTag(Ref<Tag> tag);
		void RemoveUserFunctionTagsOfType(Ref<TagType> tagType);

		Ref<Tag> CreateAutoAddressTag(Architecture* arch, uint64_t addr, const std::string& tagTypeName,
		    const std::string& data, bool unique = false);
		Ref<Tag> CreateUserAddressTag(Architecture* arch, uint64_t addr, const std::string& tagTypeName,
		    const std::string& data, bool unique = false);
		Ref<Tag> CreateAutoFunctionTag(const std::string& tagTypeName, const std::string& data, bool unique = false);
		Ref<Tag> CreateUserFunctionTag(const std::string& tagTypeName, const std::string& data, bool unique = false);

		Ref<Tag> CreateAutoAddressTag(
		    Architecture* arch, uint64_t addr, Ref<TagType> tagType, const std::string& data, bool unique = false);
		Ref<Tag> CreateUserAddressTag(
		    Architecture* arch, uint64_t addr, Ref<TagType> tagType, const std::string& data, bool unique = false);
		Ref<Tag> CreateAutoFunctionTag(Ref<TagType> tagType, const std::string& data, bool unique = false);
		Ref<Tag> CreateUserFunctionTag(Ref<TagType> tagType, const std::string& data, bool unique = false);

		void Reanalyze(BNFunctionUpdateType type = UserFunctionUpdate);
		void MarkUpdatesRequired(BNFunctionUpdateType type = UserFunctionUpdate);
		void MarkCallerUpdatesRequired(BNFunctionUpdateType type = UserFunctionUpdate);

		Ref<Workflow> GetWorkflow() const;

		void RequestAdvancedAnalysisData();
		void ReleaseAdvancedAnalysisData();
		void ReleaseAdvancedAnalysisData(size_t count);

		std::map<std::string, double> GetAnalysisPerformanceInfo();

		std::vector<DisassemblyTextLine> GetTypeTokens(DisassemblySettings* settings = nullptr);

		Confidence<RegisterValue> GetGlobalPointerValue() const;
		Confidence<RegisterValue> GetRegisterValueAtExit(uint32_t reg) const;

		/*! Whether the function is too large to automatically perform analysis

			\return Whether the function is too large to automatically perform analysis
		*/
		bool IsFunctionTooLarge();

		/*! Whether automatic analysis was skipped for this function. 

			\return Whether automatic analysis was skipped for this function. 
		*/
		bool IsAnalysisSkipped();
		BNAnalysisSkipReason GetAnalysisSkipReason();
		BNFunctionAnalysisSkipOverride GetAnalysisSkipOverride();
		void SetAnalysisSkipOverride(BNFunctionAnalysisSkipOverride skip);

		Ref<FlowGraph> GetUnresolvedStackAdjustmentGraph();

		void SetUserVariableValue(const Variable& var, uint64_t defAddr, PossibleValueSet& value);
		void ClearUserVariableValue(const Variable& var, uint64_t defAddr);
		std::map<Variable, std::map<ArchAndAddr, PossibleValueSet>> GetAllUserVariableValues();
		void ClearAllUserVariableValues();

		void RequestDebugReport(const std::string& name);

		/*! Get the name for a given label ID

			\param labelId ID For the label. Saved in the highlight token value.
			\return Name for the label
		*/
		std::string GetGotoLabelName(uint64_t labelId);

		/*! Set the name for a given label ID

			\param labelId ID For the label. Saved in the highlight token value.
			\param name New name for the label
		*/
		void SetGotoLabelName(uint64_t labelId, const std::string& name);

		BNDeadStoreElimination GetVariableDeadStoreElimination(const Variable& var);
		void SetVariableDeadStoreElimination(const Variable& var, BNDeadStoreElimination mode);

		std::map<Variable, std::set<Variable>> GetMergedVariables();
		void MergeVariables(const Variable& target, const std::set<Variable>& sources);
		void UnmergeVariables(const Variable& target, const std::set<Variable>& sources);
		std::set<Variable> GetSplitVariables();
		void SplitVariable(const Variable& var);
		void UnsplitVariable(const Variable& var);

		/*! The highest (largest) virtual address contained in a function.

			\return The highest (largest) virtual address contained in a function.
		*/
		uint64_t GetHighestAddress();

		/*! The lowest (smallest) virtual address contained in a function.

			\return The lowest (smallest) virtual address contained in a function.
		*/
		uint64_t GetLowestAddress();

		/*! All of the address ranges covered by a function

			\return All of the address ranges covered by a function
		*/
		std::vector<BNAddressRange> GetAddressRanges();

		bool GetInstructionContainingAddress(Architecture* arch, uint64_t addr, uint64_t* start);
	};

	/*!
		\ingroup function
	*/
	class AdvancedFunctionAnalysisDataRequestor
	{
		Ref<Function> m_func;

	  public:
		AdvancedFunctionAnalysisDataRequestor(Function* func = nullptr);
		AdvancedFunctionAnalysisDataRequestor(const AdvancedFunctionAnalysisDataRequestor& req);
		~AdvancedFunctionAnalysisDataRequestor();
		AdvancedFunctionAnalysisDataRequestor& operator=(const AdvancedFunctionAnalysisDataRequestor& req);

		Ref<Function> GetFunction() { return m_func; }
		void SetFunction(Function* func);
	};

	class FlowGraphNode;

	/*!
		\ingroup flowgraph
	*/
	struct FlowGraphEdge
	{
		BNBranchType type;
		Ref<FlowGraphNode> target;
		std::vector<BNPoint> points;
		bool backEdge;
		BNEdgeStyle style;
	};

	/*!
		\ingroup flowgraph
	*/
	class FlowGraphNode : public CoreRefCountObject<BNFlowGraphNode, BNNewFlowGraphNodeReference, BNFreeFlowGraphNode>
	{
		std::vector<DisassemblyTextLine> m_cachedLines;
		std::vector<FlowGraphEdge> m_cachedEdges, m_cachedIncomingEdges;
		bool m_cachedLinesValid, m_cachedEdgesValid, m_cachedIncomingEdgesValid;

	  public:
		FlowGraphNode(FlowGraph* graph);
		FlowGraphNode(BNFlowGraphNode* node);

		/*! Get the FlowGraph associated with this node

			\return The FlowGraph associated with this node
		*/
		Ref<FlowGraph> GetGraph() const;

		/*! Get the Basic Block associated with this node

			\return The BasicBlock associated with this node
		*/
		Ref<BasicBlock> GetBasicBlock() const;

		/*! Set the Basic Block associated with this node

			\param block The BasicBlock associated with this node
		*/
		void SetBasicBlock(BasicBlock* block);

		/*! Flow graph block X position

			\return Flow graph block X position
		*/
		int GetX() const;

		/*! Flow graph block Y position

			\return Flow graph block Y position
		*/
		int GetY() const;

		/*! Flow graph block width

			\return Flow graph block width
		*/
		int GetWidth() const;

		/*! Flow graph block height

			\return Flow graph block height
		*/
		int GetHeight() const;

		/*! Get the list of DisassemblyTextLines for this graph node.

			\return The list of DisassemblyTextLines for this graph node.
		*/
		const std::vector<DisassemblyTextLine>& GetLines();

		/*! Set the list of DisassemblyTextLines for this graph node.

			\param lines The list of DisassemblyTextLines for this graph node.
		*/
		void SetLines(const std::vector<DisassemblyTextLine>& lines);

		/*! Get the list of outgoing edges for this flow graph node

			\return The list of outgoing edges for this flow graph node
		*/
		const std::vector<FlowGraphEdge>& GetOutgoingEdges();

		/*! Get the list of incoming edges for this flow graph node

			\return The list of incoming edges for this flow graph node
		*/
		const std::vector<FlowGraphEdge>& GetIncomingEdges();

		/*! Connects two flow graph nodes with an edge

			\param type Type of edge to add
			\param target Target node object
			\param edgeStyle 
		 	\parblock
		 	Custom style for this edge.
		 
		 	Styling for graph edge Branch Type must be set to UserDefinedBranch
		 	\endparblock
		*/
		void AddOutgoingEdge(BNBranchType type, FlowGraphNode* target, BNEdgeStyle edgeStyle = BNEdgeStyle());

		/*! Get the highlight color for the node

			\return The highlight color for the node
		*/
		BNHighlightColor GetHighlight() const;

		/*! Set the highlight color for the node

			\param color The highlight color for the node
		*/
		void SetHighlight(const BNHighlightColor& color);

		bool IsValidForGraph(FlowGraph* graph) const;
	};

	/*!
		\ingroup flowgraph
	*/
	class FlowGraphLayoutRequest : public RefCountObject
	{
		BNFlowGraphLayoutRequest* m_object;
		std::function<void()> m_completeFunc;

		static void CompleteCallback(void* ctxt);

	  public:
		FlowGraphLayoutRequest(FlowGraph* graph, const std::function<void()>& completeFunc);
		virtual ~FlowGraphLayoutRequest();

		BNFlowGraphLayoutRequest* GetObject() const { return m_object; }

		Ref<FlowGraph> GetGraph() const;
		bool IsComplete() const;
		void Abort();
	};

	/*! FlowGraph implements a directed flow graph to be shown in the UI. This class allows plugins to
			create custom flow graphs and render them in the UI using the flow graph report API.

	 	\ingroup flowgraph
	*/
	class FlowGraph : public CoreRefCountObject<BNFlowGraph, BNNewFlowGraphReference, BNFreeFlowGraph>
	{
		std::map<BNFlowGraphNode*, Ref<FlowGraphNode>> m_cachedNodes;

		static void PrepareForLayoutCallback(void* ctxt);
		static void PopulateNodesCallback(void* ctxt);
		static void CompleteLayoutCallback(void* ctxt);
		static BNFlowGraph* UpdateCallback(void* ctxt);
		static void FreeObjectCallback(void* ctxt);

	  protected:
		bool m_queryMode = false;

		FlowGraph(BNFlowGraph* graph);

		void FinishPrepareForLayout();
		virtual void PrepareForLayout();
		virtual void PopulateNodes();
		virtual void CompleteLayout();

	  public:
		FlowGraph();

		/*! Get the Function associated with this FlowGraph

			\return The Function associated with this FlowGraph
		*/
		Ref<Function> GetFunction() const;

		/*! Get the BinaryView associated with this FlowGraph

			\return The BinaryView associated with this FlowGraph
		*/
		Ref<BinaryView> GetView() const;

		/*! Set the Function associated with this FlowGraph

			\param func The Function associated with this FlowGraph
		*/
		void SetFunction(Function* func);

		/*! Set the BinaryView associated with this FlowGraph

			\param view The BinaryView associated with this FlowGraph
		*/
		void SetView(BinaryView* view);

		int GetHorizontalNodeMargin() const;
		int GetVerticalNodeMargin() const;
		void SetNodeMargins(int horiz, int vert);

		/*! Starts rendering a graph for display. Once a layout is complete, each node will contain
			coordinates and extents that can be used to render a graph with minimum additional computation.
			This function does not wait for the graph to be ready to display, but a callback can be provided
			to signal when the graph is ready.

			\param func Callback to execute once layout is complete.
			\return 
		*/
		Ref<FlowGraphLayoutRequest> StartLayout(const std::function<void()>& func);

		/*! Check whether layout is complete

			\return Whether layout is complete
		*/
		bool IsLayoutComplete();

		/*! Get the list of nodes in the graph

			\return List of nodes in the graph
		*/
		std::vector<Ref<FlowGraphNode>> GetNodes();

		/*! Retrieve node by index

			\param i Index of the node to retrieve 
			\return The flow graph node at that index
		*/
		Ref<FlowGraphNode> GetNode(size_t i);

		/*! Whether the FlowGraph has any nodes added

			\return Whether the FlowGraph has any nodes added
		*/
		bool HasNodes() const;

		/*! Add a node to this flowgraph

			\param node Node to be added.
			\return Index of the node
		*/
		size_t AddNode(FlowGraphNode* node);

		/*! Flow graph width

			\return Flow graph width
		*/
		int GetWidth() const;

		/*! Flow graph height

			\return Flow graph height
		*/
		int GetHeight() const;
		std::vector<Ref<FlowGraphNode>> GetNodesInRegion(int left, int top, int right, int bottom);

		/*! Whether this graph is representing IL.

			\return Whether this graph is representing IL.
		*/
		bool IsILGraph() const;

		/*! Whether this graph is representing Low Level IL.

			\return Whether this graph is representing Low Level IL.
		*/
		bool IsLowLevelILGraph() const;

		/*! Whether this graph is representing Medium Level IL.

			\return Whether this graph is representing Medium Level IL.
		*/
		bool IsMediumLevelILGraph() const;

		/*! Whether this graph is representing High Level IL.

			\return Whether this graph is representing High Level IL.
		*/
		bool IsHighLevelILGraph() const;

		/*! Get the associated Low Level IL Function

			\return The associated Low Level IL Function
		*/
		Ref<LowLevelILFunction> GetLowLevelILFunction() const;

		/*! Get the associated Medium Level IL Function

			\return The associated Medium Level IL Function
		*/
		Ref<MediumLevelILFunction> GetMediumLevelILFunction() const;

		/*! Get the associated High Level IL Function

			\return The associated High Level IL Function
		*/
		Ref<HighLevelILFunction> GetHighLevelILFunction() const;

		/*! Set the associated Low Level IL Function

			\param func The associated function
		*/
		void SetLowLevelILFunction(LowLevelILFunction* func);

		/*! Set the associated Medium Level IL Function

			\param func The associated function
		*/
		void SetMediumLevelILFunction(MediumLevelILFunction* func);

		/*! Set the associated High Level IL Function

			\param func The associated function
		*/
		void SetHighLevelILFunction(HighLevelILFunction* func);

		/*! Display a flowgraph with a given title.

			\param title Title for the flowgraph
		*/
		void Show(const std::string& title);

		virtual bool HasUpdates() const;

		virtual Ref<FlowGraph> Update();

		void SetOption(BNFlowGraphOption option, bool value = true);
		bool IsOptionSet(BNFlowGraphOption option);
	};

	/*!
		\ingroup flowgraph
	*/
	class CoreFlowGraph : public FlowGraph
	{
	  public:
		CoreFlowGraph(BNFlowGraph* graph);
		virtual bool HasUpdates() const override;
		virtual Ref<FlowGraph> Update() override;
	};

	/*!
		\ingroup lowlevelil
	*/
	struct LowLevelILLabel : public BNLowLevelILLabel
	{
		LowLevelILLabel();
	};

	struct ILSourceLocation
	{
		uint64_t address;
		uint32_t sourceOperand;
		bool valid;

		ILSourceLocation() : valid(false) {}

		ILSourceLocation(uint64_t addr, uint32_t operand) : address(addr), sourceOperand(operand), valid(true) {}

		ILSourceLocation(const BNLowLevelILInstruction& instr) :
		    address(instr.address), sourceOperand(instr.sourceOperand), valid(true)
		{}

		ILSourceLocation(const BNMediumLevelILInstruction& instr) :
		    address(instr.address), sourceOperand(instr.sourceOperand), valid(true)
		{}

		ILSourceLocation(const BNHighLevelILInstruction& instr) :
		    address(instr.address), sourceOperand(instr.sourceOperand), valid(true)
		{}
	};

	struct LowLevelILInstruction;
	struct RegisterOrFlag;
	struct SSARegister;
	struct SSARegisterStack;
	struct SSAFlag;
	struct SSARegisterOrFlag;

	/*!
		\ingroup lowlevelil
	*/
	class LowLevelILFunction :
	    public CoreRefCountObject<BNLowLevelILFunction, BNNewLowLevelILFunctionReference, BNFreeLowLevelILFunction>
	{
	  public:
		LowLevelILFunction(Architecture* arch, Function* func = nullptr);
		LowLevelILFunction(BNLowLevelILFunction* func);

		Ref<Function> GetFunction() const;
		Ref<Architecture> GetArchitecture() const;

		void PrepareToCopyFunction(LowLevelILFunction* func);
		void PrepareToCopyBlock(BasicBlock* block);
		BNLowLevelILLabel* GetLabelForSourceInstruction(size_t i);

		uint64_t GetCurrentAddress() const;
		void SetCurrentAddress(Architecture* arch, uint64_t addr);
		size_t GetInstructionStart(Architecture* arch, uint64_t addr);

		void ClearIndirectBranches();
		void SetIndirectBranches(const std::vector<ArchAndAddr>& branches);

		// Get a list of registers used in the LLIL function
		std::vector<uint32_t> GetRegisters();
		std::vector<uint32_t> GetRegisterStacks();
		std::vector<uint32_t> GetFlags();

		// Get a list of SSA registers used in the LLIL SSA function, without versions.
		std::vector<SSARegister> GetSSARegistersWithoutVersions();
		std::vector<SSARegisterStack> GetSSARegisterStacksWithoutVersions();
		std::vector<SSAFlag> GetSSAFlagsWithoutVersions();

		// Get a list of SSA registers used in the LLIL SSA function, with versions
		std::vector<SSARegister> GetSSARegisters();
		std::vector<SSARegisterStack> GetSSARegisterStacks();
		std::vector<SSAFlag> GetSSAFlags();

		ExprId AddExpr(BNLowLevelILOperation operation, size_t size, uint32_t flags, ExprId a = 0, ExprId b = 0,
		    ExprId c = 0, ExprId d = 0);
		ExprId AddExprWithLocation(BNLowLevelILOperation operation, uint64_t addr, uint32_t sourceOperand, size_t size,
		    uint32_t flags, ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0);
		ExprId AddExprWithLocation(BNLowLevelILOperation operation, const ILSourceLocation& loc, size_t size,
		    uint32_t flags, ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0);
		ExprId AddInstruction(ExprId expr);

		ExprId Nop(const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegister(size_t size, uint32_t reg, ExprId val, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterSplit(size_t size, uint32_t high, uint32_t low, ExprId val, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterSSA(
		    size_t size, const SSARegister& reg, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterSSAPartial(size_t size, const SSARegister& fullReg, uint32_t partialReg, ExprId val,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterSplitSSA(size_t size, const SSARegister& high, const SSARegister& low, ExprId val,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterStackTopRelative(size_t size, uint32_t regStack, ExprId entry, ExprId val, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackPush(size_t size, uint32_t regStack, ExprId val, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterStackTopRelativeSSA(size_t size, uint32_t regStack, size_t destVersion, size_t srcVersion,
		    ExprId entry, const SSARegister& top, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterStackAbsoluteSSA(size_t size, uint32_t regStack, size_t destVersion, size_t srcVersion,
		    uint32_t reg, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetFlag(uint32_t flag, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetFlagSSA(const SSAFlag& flag, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Load(size_t size, ExprId addr, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LoadSSA(
		    size_t size, ExprId addr, size_t sourceMemoryVer, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Store(
		    size_t size, ExprId addr, ExprId val, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId StoreSSA(size_t size, ExprId addr, ExprId val, size_t newMemoryVer, size_t prevMemoryVer,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Push(size_t size, ExprId val, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Pop(size_t size, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Register(size_t size, uint32_t reg, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterSSA(size_t size, const SSARegister& reg, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterSSAPartial(size_t size, const SSARegister& fullReg, uint32_t partialReg,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterSplit(
		    size_t size, uint32_t high, uint32_t low, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterSplitSSA(size_t size, const SSARegister& high, const SSARegister& low,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackTopRelative(
		    size_t size, uint32_t regStack, ExprId entry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackPop(
		    size_t size, uint32_t regStack, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackFreeReg(uint32_t reg, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackFreeTopRelative(
		    uint32_t regStack, ExprId entry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackTopRelativeSSA(size_t size, const SSARegisterStack& regStack, ExprId entry,
		    const SSARegister& top, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackAbsoluteSSA(size_t size, const SSARegisterStack& regStack, uint32_t reg,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackFreeTopRelativeSSA(uint32_t regStack, size_t destVersion, size_t srcVersion, ExprId entry,
		    const SSARegister& top, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackFreeAbsoluteSSA(uint32_t regStack, size_t destVersion, size_t srcVersion, uint32_t reg,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Const(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ConstPointer(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ExternPointer(
		    size_t size, uint64_t val, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstRaw(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstSingle(float val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstDouble(double val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Flag(uint32_t flag, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagSSA(const SSAFlag& flag, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagBit(size_t size, uint32_t flag, size_t bitIndex, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagBitSSA(
		    size_t size, const SSAFlag& flag, size_t bitIndex, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Add(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddCarry(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Sub(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SubBorrow(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId And(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Or(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Xor(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ShiftLeft(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LogicalShiftRight(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ArithShiftRight(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateLeft(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateLeftCarry(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateRight(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateRightCarry(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Mult(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MultDoublePrecUnsigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MultDoublePrecSigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivUnsigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivDoublePrecUnsigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivSigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivDoublePrecSigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModUnsigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModDoublePrecUnsigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModSigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModDoublePrecSigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Neg(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Not(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SignExtend(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ZeroExtend(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LowPart(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Jump(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId JumpTo(ExprId dest, const std::map<uint64_t, BNLowLevelILLabel*>& targets,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Call(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallStackAdjust(ExprId dest, int64_t adjust, const std::map<uint32_t, int32_t>& regStackAdjust,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCall(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallSSA(const std::vector<SSARegister>& output, ExprId dest, const std::vector<ExprId>& params,
		    const SSARegister& stack, size_t newMemoryVer, size_t prevMemoryVer,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SystemCallSSA(const std::vector<SSARegister>& output, const std::vector<ExprId>& params,
		    const SSARegister& stack, size_t newMemoryVer, size_t prevMemoryVer,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCallSSA(const std::vector<SSARegister>& output, ExprId dest, const std::vector<ExprId>& params,
		    const SSARegister& stack, size_t newMemoryVer, size_t prevMemoryVer,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Return(size_t dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId NoReturn(const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagCondition(
		    BNLowLevelILFlagCondition cond, uint32_t semClass = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagGroup(uint32_t semGroup, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareNotEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedLessThan(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedLessThan(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedLessEqual(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedLessEqual(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedGreaterEqual(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedGreaterEqual(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedGreaterThan(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedGreaterThan(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId TestBit(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId BoolToInt(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SystemCall(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Intrinsic(const std::vector<RegisterOrFlag>& outputs, uint32_t intrinsic,
		    const std::vector<ExprId>& params, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId IntrinsicSSA(const std::vector<SSARegisterOrFlag>& outputs, uint32_t intrinsic,
		    const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Breakpoint(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Trap(int64_t num, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Undefined(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Unimplemented(const ILSourceLocation& loc = ILSourceLocation());
		ExprId UnimplementedMemoryRef(size_t size, ExprId addr, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterPhi(const SSARegister& dest, const std::vector<SSARegister>& sources,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackPhi(const SSARegisterStack& dest, const std::vector<SSARegisterStack>& sources,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagPhi(
		    const SSAFlag& dest, const std::vector<SSAFlag>& sources, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MemoryPhi(
		    size_t dest, const std::vector<size_t>& sources, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatAdd(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatSub(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatMult(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatDiv(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatSqrt(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatNeg(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatAbs(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatToInt(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId IntToFloat(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConvert(
		    size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RoundToInt(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Floor(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Ceil(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatTrunc(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareNotEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareLessThan(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareLessEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareGreaterEqual(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareGreaterThan(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareOrdered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareUnordered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		ExprId Goto(BNLowLevelILLabel& label, const ILSourceLocation& loc = ILSourceLocation());
		ExprId If(ExprId operand, BNLowLevelILLabel& t, BNLowLevelILLabel& f,
		    const ILSourceLocation& loc = ILSourceLocation());
		void MarkLabel(BNLowLevelILLabel& label);

		std::vector<uint64_t> GetOperandList(ExprId i, size_t listOperand);
		ExprId AddLabelMap(const std::map<uint64_t, BNLowLevelILLabel*>& labels);
		ExprId AddOperandList(const std::vector<ExprId> operands);
		ExprId AddIndexList(const std::vector<size_t> operands);
		ExprId AddRegisterOrFlagList(const std::vector<RegisterOrFlag>& regs);
		ExprId AddSSARegisterList(const std::vector<SSARegister>& regs);
		ExprId AddSSARegisterStackList(const std::vector<SSARegisterStack>& regStacks);
		ExprId AddSSAFlagList(const std::vector<SSAFlag>& flags);
		ExprId AddSSARegisterOrFlagList(const std::vector<SSARegisterOrFlag>& regs);

		ExprId GetExprForRegisterOrConstant(const BNRegisterOrConstant& operand, size_t size);
		ExprId GetNegExprForRegisterOrConstant(const BNRegisterOrConstant& operand, size_t size);
		ExprId GetExprForFlagOrConstant(const BNRegisterOrConstant& operand);
		ExprId GetExprForRegisterOrConstantOperation(
		    BNLowLevelILOperation op, size_t size, BNRegisterOrConstant* operands, size_t operandCount);

		ExprId Operand(size_t n, ExprId expr);

		BNLowLevelILInstruction GetRawExpr(size_t i) const;
		LowLevelILInstruction operator[](size_t i);
		LowLevelILInstruction GetInstruction(size_t i);
		LowLevelILInstruction GetExpr(size_t i);
		size_t GetIndexForInstruction(size_t i) const;
		size_t GetInstructionForExpr(size_t expr) const;
		size_t GetInstructionCount() const;
		size_t GetExprCount() const;

		void UpdateInstructionOperand(size_t i, size_t operandIndex, ExprId value);
		void ReplaceExpr(size_t expr, size_t newExpr);

		void AddLabelForAddress(Architecture* arch, ExprId addr);
		BNLowLevelILLabel* GetLabelForAddress(Architecture* arch, ExprId addr);

		void Finalize();
		void GenerateSSAForm();

		bool GetExprText(Architecture* arch, ExprId expr, std::vector<InstructionTextToken>& tokens);
		bool GetInstructionText(
		    Function* func, Architecture* arch, size_t i, std::vector<InstructionTextToken>& tokens);

		uint32_t GetTemporaryRegisterCount();
		uint32_t GetTemporaryFlagCount();

		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;
		Ref<BasicBlock> GetBasicBlockForInstruction(size_t i) const;

		Ref<LowLevelILFunction> GetSSAForm() const;
		Ref<LowLevelILFunction> GetNonSSAForm() const;
		size_t GetSSAInstructionIndex(size_t instr) const;
		size_t GetNonSSAInstructionIndex(size_t instr) const;
		size_t GetSSAExprIndex(size_t instr) const;
		size_t GetNonSSAExprIndex(size_t instr) const;

		size_t GetSSARegisterDefinition(const SSARegister& reg) const;
		size_t GetSSAFlagDefinition(const SSAFlag& flag) const;
		size_t GetSSAMemoryDefinition(size_t version) const;
		std::set<size_t> GetSSARegisterUses(const SSARegister& reg) const;
		std::set<size_t> GetSSAFlagUses(const SSAFlag& flag) const;
		std::set<size_t> GetSSAMemoryUses(size_t version) const;

		RegisterValue GetSSARegisterValue(const SSARegister& reg);
		RegisterValue GetSSAFlagValue(const SSAFlag& flag);

		RegisterValue GetExprValue(size_t expr);
		RegisterValue GetExprValue(const LowLevelILInstruction& expr);
		PossibleValueSet GetPossibleExprValues(
		    size_t expr, const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleExprValues(const LowLevelILInstruction& expr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());

		RegisterValue GetRegisterValueAtInstruction(uint32_t reg, size_t instr);
		RegisterValue GetRegisterValueAfterInstruction(uint32_t reg, size_t instr);
		PossibleValueSet GetPossibleRegisterValuesAtInstruction(uint32_t reg, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleRegisterValuesAfterInstruction(uint32_t reg, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		RegisterValue GetFlagValueAtInstruction(uint32_t flag, size_t instr);
		RegisterValue GetFlagValueAfterInstruction(uint32_t flag, size_t instr);
		PossibleValueSet GetPossibleFlagValuesAtInstruction(uint32_t flag, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleFlagValuesAfterInstruction(uint32_t flag, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		RegisterValue GetStackContentsAtInstruction(int32_t offset, size_t len, size_t instr);
		RegisterValue GetStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr);
		PossibleValueSet GetPossibleStackContentsAtInstruction(int32_t offset, size_t len, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());

		Ref<MediumLevelILFunction> GetMediumLevelIL() const;
		Ref<MediumLevelILFunction> GetMappedMediumLevelIL() const;
		size_t GetMediumLevelILInstructionIndex(size_t instr) const;
		size_t GetMediumLevelILExprIndex(size_t expr) const;
		std::set<size_t> GetMediumLevelILExprIndexes(size_t expr) const;
		size_t GetMappedMediumLevelILInstructionIndex(size_t instr) const;
		size_t GetMappedMediumLevelILExprIndex(size_t expr) const;

		static bool IsConstantType(BNLowLevelILOperation type)
		{
			return type == LLIL_CONST || type == LLIL_CONST_PTR || type == LLIL_EXTERN_PTR;
		}

		Ref<FlowGraph> CreateFunctionGraph(DisassemblySettings* settings = nullptr);
	};

	/*!
		\ingroup mediumlevelil
	*/
	struct MediumLevelILLabel : public BNMediumLevelILLabel
	{
		MediumLevelILLabel();
	};

	struct MediumLevelILInstruction;

	/*!
		\ingroup mediumlevelil
	*/
	class MediumLevelILFunction :
	    public CoreRefCountObject<BNMediumLevelILFunction, BNNewMediumLevelILFunctionReference,
	        BNFreeMediumLevelILFunction>
	{
	  public:
		MediumLevelILFunction(Architecture* arch, Function* func = nullptr);
		MediumLevelILFunction(BNMediumLevelILFunction* func);

		Ref<Function> GetFunction() const;
		Ref<Architecture> GetArchitecture() const;

		uint64_t GetCurrentAddress() const;
		void SetCurrentAddress(Architecture* arch, uint64_t addr);
		size_t GetInstructionStart(Architecture* arch, uint64_t addr);

		void PrepareToCopyFunction(MediumLevelILFunction* func);
		void PrepareToCopyBlock(BasicBlock* block);
		BNMediumLevelILLabel* GetLabelForSourceInstruction(size_t i);

		ExprId AddExpr(BNMediumLevelILOperation operation, size_t size, ExprId a = 0, ExprId b = 0, ExprId c = 0,
		    ExprId d = 0, ExprId e = 0);
		ExprId AddExprWithLocation(BNMediumLevelILOperation operation, uint64_t addr, uint32_t sourceOperand,
		    size_t size, ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0, ExprId e = 0);
		ExprId AddExprWithLocation(BNMediumLevelILOperation operation, const ILSourceLocation& loc, size_t size,
		    ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0, ExprId e = 0);

		ExprId Nop(const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVar(size_t size, const Variable& dest, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarField(size_t size, const Variable& dest, uint64_t offset, ExprId src,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarSplit(size_t size, const Variable& high, const Variable& low, ExprId src,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarSSA(
		    size_t size, const SSAVariable& dest, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarSSAField(size_t size, const Variable& dest, size_t newVersion, size_t prevVersion, uint64_t offset,
		    ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarSSASplit(size_t size, const SSAVariable& high, const SSAVariable& low, ExprId src,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarAliased(size_t size, const Variable& dest, size_t newMemVersion, size_t prevMemVersion, ExprId src,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarAliasedField(size_t size, const Variable& dest, size_t newMemVersion, size_t prevMemVersion,
		    uint64_t offset, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Load(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LoadStruct(size_t size, ExprId src, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LoadSSA(size_t size, ExprId src, size_t memVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LoadStructSSA(size_t size, ExprId src, uint64_t offset, size_t memVersion,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Store(size_t size, ExprId dest, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId StoreStruct(
		    size_t size, ExprId dest, uint64_t offset, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId StoreSSA(size_t size, ExprId dest, size_t newMemVersion, size_t prevMemVersion, ExprId src,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId StoreStructSSA(size_t size, ExprId dest, uint64_t offset, size_t newMemVersion, size_t prevMemVersion,
		    ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Var(size_t size, const Variable& src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarField(
		    size_t size, const Variable& src, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarSplit(
		    size_t size, const Variable& high, const Variable& low, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarSSA(size_t size, const SSAVariable& src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarSSAField(
		    size_t size, const SSAVariable& src, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarAliased(
		    size_t size, const Variable& src, size_t memVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarAliasedField(size_t size, const Variable& src, size_t memVersion, uint64_t offset,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarSplitSSA(size_t size, const SSAVariable& high, const SSAVariable& low,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddressOf(const Variable& var, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddressOfField(const Variable& var, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Const(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ConstPointer(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ExternPointer(
		    size_t size, uint64_t val, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstRaw(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstSingle(float val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstDouble(double val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ImportedAddress(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Add(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddWithCarry(
		    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Sub(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SubWithBorrow(
		    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId And(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Or(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Xor(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ShiftLeft(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LogicalShiftRight(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ArithShiftRight(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateLeft(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateLeftCarry(
		    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateRight(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateRightCarry(
		    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Mult(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MultDoublePrecSigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MultDoublePrecUnsigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivDoublePrecSigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivDoublePrecUnsigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModDoublePrecSigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModDoublePrecUnsigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Neg(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Not(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SignExtend(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ZeroExtend(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LowPart(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Jump(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId JumpTo(ExprId dest, const std::map<uint64_t, BNMediumLevelILLabel*>& targets,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId ReturnHint(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Call(const std::vector<Variable>& output, ExprId dest, const std::vector<ExprId>& params,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallUntyped(const std::vector<Variable>& output, ExprId dest, const std::vector<Variable>& params,
		    ExprId stack, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Syscall(const std::vector<Variable>& output, const std::vector<ExprId>& params,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SyscallUntyped(const std::vector<Variable>& output, const std::vector<Variable>& params, ExprId stack,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCall(const std::vector<Variable>& output, ExprId dest, const std::vector<ExprId>& params,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCallUntyped(const std::vector<Variable>& output, ExprId dest, const std::vector<Variable>& params,
		    ExprId stack, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallSSA(const std::vector<SSAVariable>& output, ExprId dest, const std::vector<ExprId>& params,
		    size_t newMemVersion, size_t prevMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallUntypedSSA(const std::vector<SSAVariable>& output, ExprId dest,
		    const std::vector<SSAVariable>& params, size_t newMemVersion, size_t prevMemVersion, ExprId stack,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SyscallSSA(const std::vector<SSAVariable>& output, const std::vector<ExprId>& params,
		    size_t newMemVersion, size_t prevMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SyscallUntypedSSA(const std::vector<SSAVariable>& output, const std::vector<SSAVariable>& params,
		    size_t newMemVersion, size_t prevMemVersion, ExprId stack,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCallSSA(const std::vector<SSAVariable>& output, ExprId dest, const std::vector<ExprId>& params,
		    size_t newMemVersion, size_t prevMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCallUntypedSSA(const std::vector<SSAVariable>& output, ExprId dest,
		    const std::vector<SSAVariable>& params, size_t newMemVersion, size_t prevMemVersion, ExprId stack,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Return(const std::vector<ExprId>& sources, const ILSourceLocation& loc = ILSourceLocation());
		ExprId NoReturn(const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareNotEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedLessThan(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedLessThan(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedLessEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedLessEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedGreaterEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedGreaterEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedGreaterThan(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedGreaterThan(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId TestBit(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId BoolToInt(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddOverflow(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Breakpoint(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Trap(int64_t vector, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Intrinsic(const std::vector<Variable>& outputs, uint32_t intrinsic, const std::vector<ExprId>& params,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId IntrinsicSSA(const std::vector<SSAVariable>& outputs, uint32_t intrinsic,
		    const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FreeVarSlot(const Variable& var, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FreeVarSlotSSA(const Variable& var, size_t newVersion, size_t prevVersion,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Undefined(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Unimplemented(const ILSourceLocation& loc = ILSourceLocation());
		ExprId UnimplementedMemoryRef(size_t size, ExprId target, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarPhi(const SSAVariable& dest, const std::vector<SSAVariable>& sources,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId MemoryPhi(size_t destMemVersion, const std::vector<size_t>& sourceMemVersions,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatAdd(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatSub(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatMult(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatDiv(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatSqrt(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatNeg(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatAbs(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatToInt(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId IntToFloat(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConvert(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RoundToInt(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Floor(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Ceil(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatTrunc(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareNotEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareLessThan(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareLessEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareGreaterEqual(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareGreaterThan(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareOrdered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareUnordered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		ExprId Goto(BNMediumLevelILLabel& label, const ILSourceLocation& loc = ILSourceLocation());
		ExprId If(ExprId operand, BNMediumLevelILLabel& t, BNMediumLevelILLabel& f,
		    const ILSourceLocation& loc = ILSourceLocation());
		void MarkLabel(BNMediumLevelILLabel& label);

		ExprId AddInstruction(ExprId expr);

		std::vector<uint64_t> GetOperandList(ExprId i, size_t listOperand);
		ExprId AddLabelMap(const std::map<uint64_t, BNMediumLevelILLabel*>& labels);
		ExprId AddOperandList(const std::vector<ExprId> operands);
		ExprId AddIndexList(const std::vector<size_t>& operands);
		ExprId AddVariableList(const std::vector<Variable>& vars);
		ExprId AddSSAVariableList(const std::vector<SSAVariable>& vars);

		BNMediumLevelILInstruction GetRawExpr(size_t i) const;
		MediumLevelILInstruction operator[](size_t i);
		MediumLevelILInstruction GetInstruction(size_t i);
		MediumLevelILInstruction GetExpr(size_t i);
		size_t GetIndexForInstruction(size_t i) const;
		size_t GetInstructionForExpr(size_t expr) const;
		size_t GetInstructionCount() const;
		size_t GetExprCount() const;

		void UpdateInstructionOperand(size_t i, size_t operandIndex, ExprId value);
		void MarkInstructionForRemoval(size_t i);
		void ReplaceInstruction(size_t i, ExprId expr);
		void ReplaceExpr(size_t expr, size_t newExpr);

		void Finalize();
		void GenerateSSAForm(bool analyzeConditionals = true, bool handleAliases = true,
		    const std::set<Variable>& knownNotAliases = std::set<Variable>(),
		    const std::set<Variable>& knownAliases = std::set<Variable>());

		bool GetExprText(Architecture* arch, ExprId expr, std::vector<InstructionTextToken>& tokens,
		    DisassemblySettings* settings = nullptr);
		bool GetInstructionText(Function* func, Architecture* arch, size_t i, std::vector<InstructionTextToken>& tokens,
		    DisassemblySettings* settings = nullptr);

		void VisitInstructions(
		    const std::function<void(BasicBlock* block, const MediumLevelILInstruction& instr)>& func);
		void VisitAllExprs(const std::function<bool(BasicBlock* block, const MediumLevelILInstruction& expr)>& func);

		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;
		Ref<BasicBlock> GetBasicBlockForInstruction(size_t i) const;

		Ref<MediumLevelILFunction> GetSSAForm() const;
		Ref<MediumLevelILFunction> GetNonSSAForm() const;
		size_t GetSSAInstructionIndex(size_t instr) const;
		size_t GetNonSSAInstructionIndex(size_t instr) const;
		size_t GetSSAExprIndex(size_t instr) const;
		size_t GetNonSSAExprIndex(size_t instr) const;

		size_t GetSSAVarDefinition(const SSAVariable& var) const;
		size_t GetSSAMemoryDefinition(size_t version) const;
		std::set<size_t> GetSSAVarUses(const SSAVariable& var) const;
		std::set<size_t> GetSSAMemoryUses(size_t version) const;
		bool IsSSAVarLive(const SSAVariable& var) const;

		std::set<size_t> GetVariableDefinitions(const Variable& var) const;
		std::set<size_t> GetVariableUses(const Variable& var) const;

		RegisterValue GetSSAVarValue(const SSAVariable& var);
		RegisterValue GetExprValue(size_t expr);
		RegisterValue GetExprValue(const MediumLevelILInstruction& expr);
		PossibleValueSet GetPossibleSSAVarValues(const SSAVariable& var, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleExprValues(
		    size_t expr, const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleExprValues(const MediumLevelILInstruction& expr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());

		size_t GetSSAVarVersionAtInstruction(const Variable& var, size_t instr) const;
		size_t GetSSAMemoryVersionAtInstruction(size_t instr) const;
		Variable GetVariableForRegisterAtInstruction(uint32_t reg, size_t instr) const;
		Variable GetVariableForFlagAtInstruction(uint32_t flag, size_t instr) const;
		Variable GetVariableForStackLocationAtInstruction(int64_t offset, size_t instr) const;

		RegisterValue GetRegisterValueAtInstruction(uint32_t reg, size_t instr);
		RegisterValue GetRegisterValueAfterInstruction(uint32_t reg, size_t instr);
		PossibleValueSet GetPossibleRegisterValuesAtInstruction(uint32_t reg, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleRegisterValuesAfterInstruction(uint32_t reg, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		RegisterValue GetFlagValueAtInstruction(uint32_t flag, size_t instr);
		RegisterValue GetFlagValueAfterInstruction(uint32_t flag, size_t instr);
		PossibleValueSet GetPossibleFlagValuesAtInstruction(uint32_t flag, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleFlagValuesAfterInstruction(uint32_t flag, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		RegisterValue GetStackContentsAtInstruction(int32_t offset, size_t len, size_t instr);
		RegisterValue GetStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr);
		PossibleValueSet GetPossibleStackContentsAtInstruction(int32_t offset, size_t len, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());

		BNILBranchDependence GetBranchDependenceAtInstruction(size_t curInstr, size_t branchInstr) const;
		std::unordered_map<size_t, BNILBranchDependence> GetAllBranchDependenceAtInstruction(size_t instr) const;

		Ref<LowLevelILFunction> GetLowLevelIL() const;
		size_t GetLowLevelILInstructionIndex(size_t instr) const;
		size_t GetLowLevelILExprIndex(size_t expr) const;
		std::set<size_t> GetLowLevelILExprIndexes(size_t expr) const;
		Ref<HighLevelILFunction> GetHighLevelIL() const;
		size_t GetHighLevelILInstructionIndex(size_t instr) const;
		size_t GetHighLevelILExprIndex(size_t expr) const;
		std::set<size_t> GetHighLevelILExprIndexes(size_t expr) const;

		Confidence<Ref<Type>> GetExprType(size_t expr);
		Confidence<Ref<Type>> GetExprType(const MediumLevelILInstruction& expr);

		/*! SetExprType sets the type of a given expression.

			\warning This method is only meant for workflows or for debugging purposes, since the changes they make
			are not persistent and get lost after a database save and reload. To make persistent changes to the analysis,
			one should use other APIs to, for example, change the type of variables. The analysis will then propagate the
			type of the variable and update the type of related expressions.

		    \param expr index of the expression to set
		    \param type new type of the expression
		*/
		void SetExprType(size_t expr, const Confidence<Ref<Type>>& type);
		void SetExprType(const MediumLevelILInstruction& expr, const Confidence<Ref<Type>>& type);

		static bool IsConstantType(BNMediumLevelILOperation op)
		{
			return op == MLIL_CONST || op == MLIL_CONST_PTR || op == MLIL_EXTERN_PTR;
		}

		Ref<FlowGraph> CreateFunctionGraph(DisassemblySettings* settings = nullptr);

		std::set<size_t> GetLiveInstructionsForVariable(const Variable& var, bool includeLastUse = true);

		Variable GetSplitVariableForDefinition(const Variable& var, size_t instrIndex);
	};

	struct HighLevelILInstruction;

	/*!
		\ingroup highlevelil
	*/
	class HighLevelILFunction :
	    public CoreRefCountObject<BNHighLevelILFunction, BNNewHighLevelILFunctionReference, BNFreeHighLevelILFunction>
	{
	  public:
		HighLevelILFunction(Architecture* arch, Function* func = nullptr);
		HighLevelILFunction(BNHighLevelILFunction* func);

		Ref<Function> GetFunction() const;
		Ref<Architecture> GetArchitecture() const;

		uint64_t GetCurrentAddress() const;
		void SetCurrentAddress(Architecture* arch, uint64_t addr);

		HighLevelILInstruction GetRootExpr();
		void SetRootExpr(ExprId expr);
		void SetRootExpr(const HighLevelILInstruction& expr);

		ExprId AddExpr(BNHighLevelILOperation operation, size_t size, ExprId a = 0, ExprId b = 0, ExprId c = 0,
		    ExprId d = 0, ExprId e = 0);
		ExprId AddExprWithLocation(BNHighLevelILOperation operation, uint64_t addr, uint32_t sourceOperand, size_t size,
		    ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0, ExprId e = 0);
		ExprId AddExprWithLocation(BNHighLevelILOperation operation, const ILSourceLocation& loc, size_t size,
		    ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0, ExprId e = 0);

		ExprId Nop(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Block(const std::vector<ExprId>& exprs, const ILSourceLocation& loc = ILSourceLocation());
		ExprId If(
		    ExprId condition, ExprId trueExpr, ExprId falseExpr, const ILSourceLocation& loc = ILSourceLocation());
		ExprId While(ExprId condition, ExprId loopExpr, const ILSourceLocation& loc = ILSourceLocation());
		ExprId WhileSSA(
		    ExprId conditionPhi, ExprId condition, ExprId loopExpr, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DoWhile(ExprId loopExpr, ExprId condition, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DoWhileSSA(
		    ExprId loopExpr, ExprId conditionPhi, ExprId condition, const ILSourceLocation& loc = ILSourceLocation());
		ExprId For(ExprId initExpr, ExprId condition, ExprId updateExpr, ExprId loopExpr,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId ForSSA(ExprId initExpr, ExprId conditionPhi, ExprId condition, ExprId updateExpr, ExprId loopExpr,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Switch(ExprId condition, ExprId defaultExpr, const std::vector<ExprId>& cases,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Case(
		    const std::vector<ExprId>& condition, ExprId expr, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Break(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Continue(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Jump(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Return(const std::vector<ExprId>& sources, const ILSourceLocation& loc = ILSourceLocation());
		ExprId NoReturn(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Unreachable(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Goto(uint64_t target, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Label(uint64_t target, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarDeclare(const Variable& var, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarInit(size_t size, const Variable& dest, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarInitSSA(
		    size_t size, const SSAVariable& dest, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Assign(size_t size, ExprId dest, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AssignUnpack(
		    const std::vector<ExprId>& output, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AssignMemSSA(size_t size, ExprId dest, size_t destMemVersion, ExprId src, size_t srcMemVersion,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId AssignUnpackMemSSA(const std::vector<ExprId>& output, size_t destMemVersion, ExprId src,
		    size_t srcMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Var(size_t size, const Variable& src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarSSA(size_t size, const SSAVariable& src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarPhi(const SSAVariable& dest, const std::vector<SSAVariable>& sources,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId MemPhi(
		    size_t dest, const std::vector<size_t>& sources, const ILSourceLocation& loc = ILSourceLocation());
		ExprId StructField(size_t size, ExprId src, uint64_t offset, size_t memberIndex,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId ArrayIndex(size_t size, ExprId src, ExprId idx, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ArrayIndexSSA(size_t size, ExprId src, size_t srcMemVersion, ExprId idx,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Split(size_t size, ExprId high, ExprId low, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Deref(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DerefField(size_t size, ExprId src, uint64_t offset, size_t memberIndex,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId DerefSSA(
		    size_t size, ExprId src, size_t srcMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DerefFieldSSA(size_t size, ExprId src, size_t srcMemVersion, uint64_t offset, size_t memberIndex,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddressOf(ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Const(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ConstPointer(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ExternPointer(
		    size_t size, uint64_t val, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstRaw(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstSingle(float val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstDouble(double val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ImportedAddress(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Add(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddWithCarry(
		    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Sub(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SubWithBorrow(
		    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId And(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Or(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Xor(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ShiftLeft(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LogicalShiftRight(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ArithShiftRight(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateLeft(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateLeftCarry(
		    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateRight(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateRightCarry(
		    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Mult(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MultDoublePrecSigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MultDoublePrecUnsigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivDoublePrecSigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivDoublePrecUnsigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModDoublePrecSigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModDoublePrecUnsigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Neg(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Not(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SignExtend(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ZeroExtend(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LowPart(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Call(ExprId dest, const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Syscall(const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCall(
		    ExprId dest, const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallSSA(ExprId dest, const std::vector<ExprId>& params, size_t destMemVersion, size_t srcMemVersion,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SyscallSSA(const std::vector<ExprId>& params, size_t destMemVersion, size_t srcMemVersion,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareNotEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedLessThan(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedLessThan(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedLessEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedLessEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedGreaterEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedGreaterEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedGreaterThan(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedGreaterThan(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId TestBit(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId BoolToInt(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddOverflow(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Breakpoint(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Trap(int64_t vector, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Intrinsic(
		    uint32_t intrinsic, const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId IntrinsicSSA(uint32_t intrinsic, const std::vector<ExprId>& params, size_t destMemVersion,
		    size_t srcMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Undefined(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Unimplemented(const ILSourceLocation& loc = ILSourceLocation());
		ExprId UnimplementedMemoryRef(size_t size, ExprId target, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatAdd(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatSub(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatMult(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatDiv(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatSqrt(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatNeg(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatAbs(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatToInt(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId IntToFloat(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConvert(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RoundToInt(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Floor(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Ceil(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatTrunc(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareNotEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareLessThan(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareLessEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareGreaterEqual(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareGreaterThan(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareOrdered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareUnordered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		std::vector<uint64_t> GetOperandList(ExprId i, size_t listOperand);
		ExprId AddOperandList(const std::vector<ExprId>& operands);
		ExprId AddIndexList(const std::vector<size_t>& operands);
		ExprId AddSSAVariableList(const std::vector<SSAVariable>& vars);

		BNHighLevelILInstruction GetRawExpr(size_t i) const;
		BNHighLevelILInstruction GetRawNonASTExpr(size_t i) const;
		HighLevelILInstruction operator[](size_t i);
		HighLevelILInstruction GetInstruction(size_t i);
		HighLevelILInstruction GetExpr(size_t i, bool asFullAst = true);
		size_t GetIndexForInstruction(size_t i) const;
		size_t GetInstructionForExpr(size_t expr) const;
		size_t GetInstructionCount() const;
		size_t GetExprCount() const;

		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;
		Ref<BasicBlock> GetBasicBlockForInstruction(size_t i) const;

		Ref<HighLevelILFunction> GetSSAForm() const;
		Ref<HighLevelILFunction> GetNonSSAForm() const;
		size_t GetSSAInstructionIndex(size_t instr) const;
		size_t GetNonSSAInstructionIndex(size_t instr) const;
		size_t GetSSAExprIndex(size_t instr) const;
		size_t GetNonSSAExprIndex(size_t instr) const;

		size_t GetSSAVarDefinition(const SSAVariable& var) const;
		size_t GetSSAMemoryDefinition(size_t version) const;
		std::set<size_t> GetSSAVarUses(const SSAVariable& var) const;
		std::set<size_t> GetSSAMemoryUses(size_t version) const;
		bool IsSSAVarLive(const SSAVariable& var) const;
		bool IsSSAVarLiveAt(const SSAVariable& var, const size_t instr) const;
		bool IsVarLiveAt(const Variable& var, const size_t instr) const;

		std::set<size_t> GetVariableDefinitions(const Variable& var) const;
		std::set<size_t> GetVariableUses(const Variable& var) const;
		size_t GetSSAVarVersionAtInstruction(const Variable& var, size_t instr) const;
		size_t GetSSAMemoryVersionAtInstruction(size_t instr) const;

		Ref<MediumLevelILFunction> GetMediumLevelIL() const;
		size_t GetMediumLevelILExprIndex(size_t expr) const;
		std::set<size_t> GetMediumLevelILExprIndexes(size_t expr) const;

		void UpdateInstructionOperand(size_t i, size_t operandIndex, ExprId value);
		void ReplaceExpr(size_t expr, size_t newExpr);

		void Finalize();
		void GenerateSSAForm(const std::set<Variable>& aliases = std::set<Variable>());

		std::vector<DisassemblyTextLine> GetExprText(
		    ExprId expr, bool asFullAst = true, DisassemblySettings* settings = nullptr);
		std::vector<DisassemblyTextLine> GetExprText(
		    const HighLevelILInstruction& instr, bool asFullAst = true, DisassemblySettings* settings = nullptr);
		std::vector<DisassemblyTextLine> GetInstructionText(
		    size_t i, bool asFullAst = true, DisassemblySettings* settings = nullptr);

		Confidence<Ref<Type>> GetExprType(size_t expr);
		Confidence<Ref<Type>> GetExprType(const HighLevelILInstruction& expr);

		/*! SetExprType sets the type of a given expression.

			\warning This method is only meant for workflows or for debugging purposes, since the changes they make
			are not persistent and get lost after a database save and reload. To make persistent changes to the analysis,
			one should use other APIs to, for example, change the type of variables. The analysis will then propagate the
			type of the variable and update the type of related expressions.

		    \param expr index of the expression to set
		    \param type new type of the expression
		*/
		void SetExprType(size_t expr, const Confidence<Ref<Type>>& type);
		void SetExprType(const HighLevelILInstruction& expr, const Confidence<Ref<Type>>& type);

		void VisitAllExprs(const std::function<bool(const HighLevelILInstruction& expr)>& func);

		Ref<FlowGraph> CreateFunctionGraph(DisassemblySettings* settings = nullptr);

		size_t GetExprIndexForLabel(uint64_t label);
		std::set<size_t> GetUsesForLabel(uint64_t label);
	};

	class LanguageRepresentationFunction :
	    public CoreRefCountObject<BNLanguageRepresentationFunction, BNNewLanguageRepresentationFunctionReference,
	        BNFreeLanguageRepresentationFunction>
	{
	  public:
		LanguageRepresentationFunction(Architecture* arch, Function* func = nullptr);
		LanguageRepresentationFunction(BNLanguageRepresentationFunction* func);
	};

	/*!
		\ingroup functionrecognizer
	*/
	class FunctionRecognizer
	{
		static bool RecognizeLowLevelILCallback(
		    void* ctxt, BNBinaryView* data, BNFunction* func, BNLowLevelILFunction* il);
		static bool RecognizeMediumLevelILCallback(
		    void* ctxt, BNBinaryView* data, BNFunction* func, BNMediumLevelILFunction* il);

	  public:
		FunctionRecognizer();

		static void RegisterGlobalRecognizer(FunctionRecognizer* recog);
		static void RegisterArchitectureFunctionRecognizer(Architecture* arch, FunctionRecognizer* recog);

		virtual bool RecognizeLowLevelIL(BinaryView* data, Function* func, LowLevelILFunction* il);
		virtual bool RecognizeMediumLevelIL(BinaryView* data, Function* func, MediumLevelILFunction* il);
	};

	class RelocationHandler :
	    public CoreRefCountObject<BNRelocationHandler, BNNewRelocationHandlerReference, BNFreeRelocationHandler>
	{
		static bool GetRelocationInfoCallback(
		    void* ctxt, BNBinaryView* view, BNArchitecture* arch, BNRelocationInfo* result, size_t resultCount);
		static bool ApplyRelocationCallback(
		    void* ctxt, BNBinaryView* view, BNArchitecture* arch, BNRelocation* reloc, uint8_t* dest, size_t len);
		static size_t GetOperandForExternalRelocationCallback(void* ctxt, const uint8_t* data, uint64_t addr,
		    size_t length, BNLowLevelILFunction* il, BNRelocation* relocation);

	  protected:
		RelocationHandler();
		RelocationHandler(BNRelocationHandler* handler);
		static void FreeCallback(void* ctxt);

	  public:
		virtual bool GetRelocationInfo(
		    Ref<BinaryView> view, Ref<Architecture> arch, std::vector<BNRelocationInfo>& result);
		virtual bool ApplyRelocation(
		    Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len);
		virtual size_t GetOperandForExternalRelocation(
		    const uint8_t* data, uint64_t addr, size_t length, Ref<LowLevelILFunction> il, Ref<Relocation> relocation);
	};

	class CoreRelocationHandler : public RelocationHandler
	{
	  public:
		CoreRelocationHandler(BNRelocationHandler* handler);
		virtual bool GetRelocationInfo(
		    Ref<BinaryView> view, Ref<Architecture> arch, std::vector<BNRelocationInfo>& result) override;
		virtual bool ApplyRelocation(
		    Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len) override;
		virtual size_t GetOperandForExternalRelocation(const uint8_t* data, uint64_t addr, size_t length,
		    Ref<LowLevelILFunction> il, Ref<Relocation> relocation) override;
	};

	class UpdateException : public std::exception
	{
		const std::string m_desc;

	  public:
		UpdateException(const std::string& desc) : std::exception(), m_desc(desc) {}
		virtual const char* what() const NOEXCEPT { return m_desc.c_str(); }
	};

	/*!
		\ingroup update
	*/
	struct UpdateChannel
	{
		std::string name;
		std::string description;
		std::string latestVersion;

		static std::vector<UpdateChannel> GetList();

		bool AreUpdatesAvailable(uint64_t* expireTime, uint64_t* serverTime);

		BNUpdateResult UpdateToVersion(const std::string& version);
		BNUpdateResult UpdateToVersion(
		    const std::string& version, const std::function<bool(uint64_t progress, uint64_t total)>& progress);
		BNUpdateResult UpdateToLatestVersion();
		BNUpdateResult UpdateToLatestVersion(const std::function<bool(uint64_t progress, uint64_t total)>& progress);
	};

	/*! UpdateVersion documentation
		\ingroup update
	*/
	struct UpdateVersion
	{
		std::string version;
		std::string notes;
		time_t time;

		static std::vector<UpdateVersion> GetChannelVersions(const std::string& channel);
	};

	/*!
		\ingroup plugin
	*/
	struct PluginCommandContext
	{
		Ref<BinaryView> binaryView;
		uint64_t address, length;
		size_t instrIndex;
		Ref<Function> function;
		Ref<LowLevelILFunction> lowLevelILFunction;
		Ref<MediumLevelILFunction> mediumLevelILFunction;
		Ref<HighLevelILFunction> highLevelILFunction;

		PluginCommandContext();
	};

	/*!
		The PluginCommand class is used for registering "commands" for Plugins, corresponding to code in those plugins
	 	to be executed.

	 	\ingroup plugin

	 	The proper way to use this class is via one of the \c "Register*" static methods.
	*/
	class PluginCommand
	{
		BNPluginCommand m_command;

		struct RegisteredDefaultCommand
		{
			std::function<void(BinaryView*)> action;
			std::function<bool(BinaryView*)> isValid;
		};

		struct RegisteredAddressCommand
		{
			std::function<void(BinaryView*, uint64_t)> action;
			std::function<bool(BinaryView*, uint64_t)> isValid;
		};

		struct RegisteredRangeCommand
		{
			std::function<void(BinaryView*, uint64_t, uint64_t)> action;
			std::function<bool(BinaryView*, uint64_t, uint64_t)> isValid;
		};

		struct RegisteredFunctionCommand
		{
			std::function<void(BinaryView*, Function*)> action;
			std::function<bool(BinaryView*, Function*)> isValid;
		};

		struct RegisteredLowLevelILFunctionCommand
		{
			std::function<void(BinaryView*, LowLevelILFunction*)> action;
			std::function<bool(BinaryView*, LowLevelILFunction*)> isValid;
		};

		struct RegisteredLowLevelILInstructionCommand
		{
			std::function<void(BinaryView*, const LowLevelILInstruction&)> action;
			std::function<bool(BinaryView*, const LowLevelILInstruction&)> isValid;
		};

		struct RegisteredMediumLevelILFunctionCommand
		{
			std::function<void(BinaryView*, MediumLevelILFunction*)> action;
			std::function<bool(BinaryView*, MediumLevelILFunction*)> isValid;
		};

		struct RegisteredMediumLevelILInstructionCommand
		{
			std::function<void(BinaryView*, const MediumLevelILInstruction&)> action;
			std::function<bool(BinaryView*, const MediumLevelILInstruction&)> isValid;
		};

		struct RegisteredHighLevelILFunctionCommand
		{
			std::function<void(BinaryView*, HighLevelILFunction*)> action;
			std::function<bool(BinaryView*, HighLevelILFunction*)> isValid;
		};

		struct RegisteredHighLevelILInstructionCommand
		{
			std::function<void(BinaryView*, const HighLevelILInstruction&)> action;
			std::function<bool(BinaryView*, const HighLevelILInstruction&)> isValid;
		};

		static void DefaultPluginCommandActionCallback(void* ctxt, BNBinaryView* view);
		static void AddressPluginCommandActionCallback(void* ctxt, BNBinaryView* view, uint64_t addr);
		static void RangePluginCommandActionCallback(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len);
		static void FunctionPluginCommandActionCallback(void* ctxt, BNBinaryView* view, BNFunction* func);
		static void LowLevelILFunctionPluginCommandActionCallback(
		    void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func);
		static void LowLevelILInstructionPluginCommandActionCallback(
		    void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr);
		static void MediumLevelILFunctionPluginCommandActionCallback(
		    void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func);
		static void MediumLevelILInstructionPluginCommandActionCallback(
		    void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr);
		static void HighLevelILFunctionPluginCommandActionCallback(
		    void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func);
		static void HighLevelILInstructionPluginCommandActionCallback(
		    void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr);

		static bool DefaultPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view);
		static bool AddressPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, uint64_t addr);
		static bool RangePluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len);
		static bool FunctionPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, BNFunction* func);
		static bool LowLevelILFunctionPluginCommandIsValidCallback(
		    void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func);
		static bool LowLevelILInstructionPluginCommandIsValidCallback(
		    void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr);
		static bool MediumLevelILFunctionPluginCommandIsValidCallback(
		    void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func);
		static bool MediumLevelILInstructionPluginCommandIsValidCallback(
		    void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr);
		static bool HighLevelILFunctionPluginCommandIsValidCallback(
		    void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func);
		static bool HighLevelILInstructionPluginCommandIsValidCallback(
		    void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr);

	  public:
		PluginCommand(const BNPluginCommand& cmd);
		PluginCommand(const PluginCommand& cmd);
		~PluginCommand();

		PluginCommand& operator=(const PluginCommand& cmd);

		/*! Register a command for a given BinaryView.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::Register("MyPlugin\\MyAction", "Perform an action",
				   [](BinaryView* view)
				   {
					   // Perform an action on a view
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g. "void myCommand(BinaryView* view)"
			void MyPlugin::MyCommand(BinaryView* view)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::Register("MyPlugin\\MySecondAction", "Perform an action", MyPlugin::MyCommand);
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void Register(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view)>& action);

		/*! Register a command for a given BinaryView, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::Register("MyPlugin\\MyAction", "Perform an action",
					[](BinaryView* view)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace, e.g. "void myCommand(BinaryView* view)"
			void MyPlugin::MyCommand(BinaryView* view)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::Register("MyPlugin\\MySecondAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Function that returns whether the command is allowed to be performed.
		*/
		static void Register(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view)>& action, const std::function<bool(BinaryView* view)>& isValid);

		/*! Register a command for a given BinaryView, when an address is selected.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForAddress("MyPlugin\\MyAddressAction", "Perform an action on an address",
				   [](BinaryView* view, uint64_t addr)
				   {
					   // Perform an action on a view and address
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g. "void myCommand(BinaryView* view)"
			void MyPlugin::MyCommand(BinaryView* view, uint64_t addr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForAddress("MyPlugin\\MySecondAddressAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForAddress(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr)>& action);

		/*! Register a command for a given BinaryView and an address, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForAddress("MyPlugin\\MyAddressAction", "Perform an action",
					[](BinaryView* view, uint64_t addr)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, uint64_t addr)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace, e.g. "void myCommand(BinaryView* view)"
			void MyPlugin::MyCommand(BinaryView* view, uint64_t addr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForAddress("MyPlugin\\MySecondAddressAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, uint64_t addr){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForAddress(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr)>& action,
		    const std::function<bool(BinaryView* view, uint64_t addr)>& isValid);

		/*! Register a command for a given BinaryView, when a range of address is selected.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForRange("MyPlugin\\MyRangeAction", "Perform an action on a range",
				   [](BinaryView* view, uint64_t addr, uint64_t len)
				   {
					   // Perform an action on a view and address
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g. "void myCommand(BinaryView* view)"
			void MyPlugin::MyCommand(BinaryView* view, uint64_t addr, uint64_t len)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForRange("MyPlugin\\MySecondRangeAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForRange(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr, uint64_t len)>& action);

		/*! Register a command for a given BinaryView and a range, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForRange("MyPlugin\\MyRangeAction", "Perform an action",
					[](BinaryView* view, uint64_t addr, uint64_t len)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, uint64_t addr, uint64_t len)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace, e.g. "void myCommand(BinaryView* view)"
			void MyPlugin::MyCommand(BinaryView* view, uint64_t addr, uint64_t len)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForRange("MyPlugin\\MySecondRangeAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, uint64_t addr, uint64_t len){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForRange(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr, uint64_t len)>& action,
		    const std::function<bool(BinaryView* view, uint64_t addr, uint64_t len)>& isValid);

		/*! Register a command for a given BinaryView within a function.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForFunction("MyPlugin\\MyFunctionAction", "Perform an action on a function",
				   [](BinaryView* view, Function* func)
				   {
					   // Perform an action on a view and function
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, Function* func)"
			void MyPlugin::MyCommand(BinaryView* view, Function* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForFunction("MyPlugin\\MySecondFunctionAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, Function* func)>& action);

		/*! Register a command for a given BinaryView and a function, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForFunction("MyPlugin\\MyFunctionAction", "Perform an action",
					[](BinaryView* view, Function* func)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, Function* func)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, Function* func)"
			void MyPlugin::MyCommand(BinaryView* view, Function* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForFunction("MyPlugin\\MySecondFunctionAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, Function* func){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, Function* func)>& action,
		    const std::function<bool(BinaryView* view, Function* func)>& isValid);

		/*! Register a command for a given BinaryView within a LowLevelILFunction.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForLowLevelILFunction("MyPlugin\\MyLLILFunctionAction", "Perform an action on a llil function",
				   [](BinaryView* view, LowLevelILFunction* func)
				   {
					   // Perform an action on a view and function
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, LowLevelILFunction* func)"
			void MyPlugin::MyCommand(BinaryView* view, LowLevelILFunction* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForLowLevelILFunction("MyPlugin\\MySecondLLILAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForLowLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, LowLevelILFunction* func)>& action);

		/*! Register a command for a given BinaryView and a Low Level IL function, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForLowLevelILFunction("MyPlugin\\MyLLILFunctionAction", "Perform an action",
					[](BinaryView* view, LowLevelILFunction* func)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, LowLevelILFunction* func)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, LowLevelILFunction* func)"
			void MyPlugin::MyCommand(BinaryView* view, LowLevelILFunction* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForLowLevelILFunction("MyPlugin\\MySecondLLILAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, LowLevelILFunction* func){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForLowLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, LowLevelILFunction* func)>& action,
		    const std::function<bool(BinaryView* view, LowLevelILFunction* func)>& isValid);

		/*! Register a command for a given BinaryView with a given LowLevelILInstruction.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForRegisterForLowLevelILInstruction("MyPlugin\\MyLLILInstructionAction",
		    		"Perform an action on an instruction",
				   [](BinaryView* view, LowLevelILInstruction* instr)
				   {
					   // Perform an action on a view and a LowLevelILInstruction
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, LowLevelILInstruction* instr)"
			void MyPlugin::MyCommand(BinaryView* view, LowLevelILInstruction* instr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForLowLevelILInstruction("MyPlugin\\MySecondLLILAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForLowLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const LowLevelILInstruction& instr)>& action);

		/*! Register a command for a given BinaryView and a LowLevelILInstruction, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForLowLevelILInstruction("MyPlugin\\MyLLILInstructionAction", "Perform an action",
					[](BinaryView* view, LowLevelILInstruction* instr)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, LowLevelILInstruction* instr)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, LowLevelILInstruction* instr)"
			void MyPlugin::MyCommand(BinaryView* view, LowLevelILInstruction* instr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForLowLevelILInstruction("MyPlugin\\MySecondLLILAction",
		    		"Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, LowLevelILInstruction* instr){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForLowLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const LowLevelILInstruction& instr)>& action,
		    const std::function<bool(BinaryView* view, const LowLevelILInstruction& instr)>& isValid);

		/*! Register a command for a given BinaryView within a MediumLevelILFunction.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForMediumLevelILFunction("MyPlugin\\MyMLILFunctionAction", "Perform an action on a mlil function",
				   [](BinaryView* view, MediumLevelILFunction* func)
				   {
					   // Perform an action on a view and function
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, MediumLevelILFunction* func)"
			void MyPlugin::MyCommand(BinaryView* view, MediumLevelILFunction* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForMediumLevelILFunction("MyPlugin\\MySecondMLILAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForMediumLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, MediumLevelILFunction* func)>& action);

		/*! Register a command for a given BinaryView and a Medium Level IL function, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForMediumLevelILFunction("MyPlugin\\MyMLILFunctionAction", "Perform an action",
					[](BinaryView* view, MediumLevelILFunction* func)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, MediumLevelILFunction* func)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, MediumLevelILFunction* func)"
			void MyPlugin::MyCommand(BinaryView* view, MediumLevelILFunction* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForMediumLevelILFunction("MyPlugin\\MySecondMLILAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, MediumLevelILFunction* func){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForMediumLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, MediumLevelILFunction* func)>& action,
		    const std::function<bool(BinaryView* view, MediumLevelILFunction* func)>& isValid);

		/*! Register a command for a given BinaryView with a given MediumLevelILInstruction.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForRegisterForMediumLevelILInstruction("MyPlugin\\MyMLILInstructionAction",
		    		"Perform an action on an instruction",
				   [](BinaryView* view, MediumLevelILInstruction* instr)
				   {
					   // Perform an action on a view and a MediumLevelILInstruction
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, MediumLevelILInstruction* instr)"
			void MyPlugin::MyCommand(BinaryView* view, MediumLevelILInstruction* instr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForMediumLevelILInstruction("MyPlugin\\MySecondMLILAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForMediumLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const MediumLevelILInstruction& instr)>& action);

		/*! Register a command for a given BinaryView and a MediumLevelILInstruction, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForMediumLevelILInstruction("MyPlugin\\MyMLILInstructionAction", "Perform an action",
					[](BinaryView* view, MediumLevelILInstruction* instr)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, MediumLevelILInstruction* instr)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, MediumLevelILInstruction* instr)"
			void MyPlugin::MyCommand(BinaryView* view, MediumLevelILInstruction* instr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForMediumLevelILInstruction("MyPlugin\\MySecondMLILAction",
		    		"Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, MediumLevelILInstruction* instr){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForMediumLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const MediumLevelILInstruction& instr)>& action,
		    const std::function<bool(BinaryView* view, const MediumLevelILInstruction& instr)>& isValid);

		/*! Register a command for a given BinaryView within a HighLevelILFunction.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForHighLevelILFunction("MyPlugin\\MyHLILFunctionAction", "Perform an action on a hlil function",
				   [](BinaryView* view, HighLevelILFunction* func)
				   {
					   // Perform an action on a view and function
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, HighLevelILFunction* func)"
			void MyPlugin::MyCommand(BinaryView* view, HighLevelILFunction* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForMediumLevelILFunction("MyPlugin\\MySecondHLILAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForHighLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, HighLevelILFunction* func)>& action);

		/*! Register a command for a given BinaryView and a High Level IL function, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForHighLevelILFunction("MyPlugin\\MyHLILFunctionAction", "Perform an action",
					[](BinaryView* view, HighLevelILFunction* func)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, HighLevelILFunction* func)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, HighLevelILFunction* func)"
			void MyPlugin::MyCommand(BinaryView* view, HighLevelILFunction* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForHighLevelILFunction("MyPlugin\\MySecondHLILAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, HighLevelILFunction* func){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForHighLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, HighLevelILFunction* func)>& action,
		    const std::function<bool(BinaryView* view, HighLevelILFunction* func)>& isValid);

		/*! Register a command for a given BinaryView with a given HighLevelILInstruction.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForRegisterForHighLevelILInstruction("MyPlugin\\MyHLILInstructionAction",
		    		"Perform an action on an instruction",
				   [](BinaryView* view, HighLevelILInstruction* instr)
				   {
					   // Perform an action on a view and a HighLevelILInstruction
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, HighLevelILInstruction* instr)"
			void MyPlugin::MyCommand(BinaryView* view, HighLevelILInstruction* instr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForHighLevelILInstruction("MyPlugin\\MySecondHLILAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForHighLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const HighLevelILInstruction& instr)>& action);

		/*! Register a command for a given BinaryView and a HighLevelILInstruction, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForHighLevelILInstruction("MyPlugin\\MyHLILInstructionAction", "Perform an action",
					[](BinaryView* view, HighLevelILInstruction* instr)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, HighLevelILInstruction* instr)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, HighLevelILInstruction* instr)"
			void MyPlugin::MyCommand(BinaryView* view, HighLevelILInstruction* instr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForHighLevelILInstruction("MyPlugin\\MySecondHLILAction",
		    		"Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, HighLevelILInstruction* instr){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForHighLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const HighLevelILInstruction& instr)>& action,
		    const std::function<bool(BinaryView* view, const HighLevelILInstruction& instr)>& isValid);

		/*! Get the list of registered PluginCommands

			\return The list of registered PluginCommands
		*/
		static std::vector<PluginCommand> GetList();

		/*! Get the list of valid PluginCommands for a given context

			\param ctxt The context to be used for the checks
			\return The list of valid plugin commands.
		*/
		static std::vector<PluginCommand> GetValidList(const PluginCommandContext& ctxt);

		/*! Get the name for the registered PluginCommand

			\return The name for the registered PluginCommand
		*/
		std::string GetName() const { return m_command.name; }

		/*! Get the description for the registered PluginCommand

			\return The description for the registered PluginCommand
		*/
		std::string GetDescription() const { return m_command.description; }

		/*! Get the type of the registered PluginCommand

			\return The type of the registered PluginCommand
		*/
		BNPluginCommandType GetType() const { return m_command.type; }
		const BNPluginCommand* GetObject() const { return &m_command; }

		bool IsValid(const PluginCommandContext& ctxt) const;
		void Execute(const PluginCommandContext& ctxt) const;
	};

	/*!
		\ingroup callingconvention
	*/
	class CallingConvention :
	    public CoreRefCountObject<BNCallingConvention, BNNewCallingConventionReference, BNFreeCallingConvention>
	{
	  protected:
		CallingConvention(BNCallingConvention* cc);
		CallingConvention(Architecture* arch, const std::string& name);

		static void FreeCallback(void* ctxt);

		static uint32_t* GetCallerSavedRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetCalleeSavedRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetIntegerArgumentRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetFloatArgumentRegistersCallback(void* ctxt, size_t* count);
		static void FreeRegisterListCallback(void* ctxt, uint32_t* regs);

		static bool AreArgumentRegistersSharedIndexCallback(void* ctxt);
		static bool AreArgumentRegistersUsedForVarArgsCallback(void* ctxt);
		static bool IsStackReservedForArgumentRegistersCallback(void* ctxt);
		static bool IsStackAdjustedOnReturnCallback(void* ctxt);
		static bool IsEligibleForHeuristicsCallback(void* ctxt);

		static uint32_t GetIntegerReturnValueRegisterCallback(void* ctxt);
		static uint32_t GetHighIntegerReturnValueRegisterCallback(void* ctxt);
		static uint32_t GetFloatReturnValueRegisterCallback(void* ctxt);
		static uint32_t GetGlobalPointerRegisterCallback(void* ctxt);

		static uint32_t* GetImplicitlyDefinedRegistersCallback(void* ctxt, size_t* count);
		static void GetIncomingRegisterValueCallback(
		    void* ctxt, uint32_t reg, BNFunction* func, BNRegisterValue* result);
		static void GetIncomingFlagValueCallback(void* ctxt, uint32_t reg, BNFunction* func, BNRegisterValue* result);

		static void GetIncomingVariableForParameterVariableCallback(
		    void* ctxt, const BNVariable* var, BNFunction* func, BNVariable* result);
		static void GetParameterVariableForIncomingVariableCallback(
		    void* ctxt, const BNVariable* var, BNFunction* func, BNVariable* result);

	  public:
		Ref<Architecture> GetArchitecture() const;
		std::string GetName() const;

		virtual std::vector<uint32_t> GetCallerSavedRegisters();
		virtual std::vector<uint32_t> GetCalleeSavedRegisters();

		virtual std::vector<uint32_t> GetIntegerArgumentRegisters();
		virtual std::vector<uint32_t> GetFloatArgumentRegisters();
		virtual bool AreArgumentRegistersSharedIndex();
		virtual bool AreArgumentRegistersUsedForVarArgs();
		virtual bool IsStackReservedForArgumentRegisters();
		virtual bool IsStackAdjustedOnReturn();
		virtual bool IsEligibleForHeuristics();

		virtual uint32_t GetIntegerReturnValueRegister() = 0;
		virtual uint32_t GetHighIntegerReturnValueRegister();
		virtual uint32_t GetFloatReturnValueRegister();
		virtual uint32_t GetGlobalPointerRegister();

		virtual std::vector<uint32_t> GetImplicitlyDefinedRegisters();
		virtual RegisterValue GetIncomingRegisterValue(uint32_t reg, Function* func);
		virtual RegisterValue GetIncomingFlagValue(uint32_t flag, Function* func);

		virtual Variable GetIncomingVariableForParameterVariable(const Variable& var, Function* func);
		virtual Variable GetParameterVariableForIncomingVariable(const Variable& var, Function* func);
	};

	/*!
		\ingroup callingconvention
	*/
	class CoreCallingConvention : public CallingConvention
	{
	  public:
		CoreCallingConvention(BNCallingConvention* cc);

		virtual std::vector<uint32_t> GetCallerSavedRegisters() override;
		virtual std::vector<uint32_t> GetCalleeSavedRegisters() override;

		virtual std::vector<uint32_t> GetIntegerArgumentRegisters() override;
		virtual std::vector<uint32_t> GetFloatArgumentRegisters() override;
		virtual bool AreArgumentRegistersSharedIndex() override;
		virtual bool AreArgumentRegistersUsedForVarArgs() override;
		virtual bool IsStackReservedForArgumentRegisters() override;
		virtual bool IsStackAdjustedOnReturn() override;
		virtual bool IsEligibleForHeuristics() override;

		virtual uint32_t GetIntegerReturnValueRegister() override;
		virtual uint32_t GetHighIntegerReturnValueRegister() override;
		virtual uint32_t GetFloatReturnValueRegister() override;
		virtual uint32_t GetGlobalPointerRegister() override;

		virtual std::vector<uint32_t> GetImplicitlyDefinedRegisters() override;
		virtual RegisterValue GetIncomingRegisterValue(uint32_t reg, Function* func) override;
		virtual RegisterValue GetIncomingFlagValue(uint32_t flag, Function* func) override;

		virtual Variable GetIncomingVariableForParameterVariable(const Variable& var, Function* func) override;
		virtual Variable GetParameterVariableForIncomingVariable(const Variable& var, Function* func) override;
	};

	/*!
	    Platform base class. This should be subclassed when creating a new platform

	 	\ingroup Platform
	*/
	class Platform : public CoreRefCountObject<BNPlatform, BNNewPlatformReference, BNFreePlatform>
	{
	  protected:
		Platform(Architecture* arch, const std::string& name);
		Platform(Architecture* arch, const std::string& name, const std::string& typeFile,
		    const std::vector<std::string>& includeDirs = std::vector<std::string>());

	  public:
		Platform(BNPlatform* platform);

		/*! Get the Architecture for this platform

			\return The platform architecture
		*/
		Ref<Architecture> GetArchitecture() const;

		/*! Get the name of this platform

			\return The platform namee
		*/
		std::string GetName() const;

		/*! Register a Platform

			\param os OS for the platform to register
			\param platform Platform to register
		*/
		static void Register(const std::string& os, Platform* platform);

		/*! Get a platform by name

			\param name Name of the platform to retrieve
			\return The Platform, if it exists
		*/
		static Ref<Platform> GetByName(const std::string& name);

		/*! Get the list of registered platforms

			\return The list of registered platforms
		*/
		static std::vector<Ref<Platform>> GetList();

		/*! Get the list of registered platforms by Architecture

			\param arch Architecture to get the registered platforms for
			\return The list of registered platforms by Architecture
		*/
		static std::vector<Ref<Platform>> GetList(Architecture* arch);

		/*! Get the list of registered platforms by os

			\param os OS to get the registered platforms for
			\return The list of registered platforms by Architecture
		*/
		static std::vector<Ref<Platform>> GetList(const std::string& os);

		/*! Get the list of registered platforms by OS and Architecture

			\param os OS to get the registered platforms for
			\param arch Architecture to get the registered platforms for
			\return The list of registered platforms
		*/
		static std::vector<Ref<Platform>> GetList(const std::string& os, Architecture* arch);

		/*! Get the list of operating systems

			\return The list of operating systems
		*/
		static std::vector<std::string> GetOSList();

		/*! Get the default calling convention for this platform

			\return The default calling convention
		*/
		Ref<CallingConvention> GetDefaultCallingConvention() const;

		/*! Get the cdecl CallingConvention

			\return The cdecl CallingConvention
		*/
		Ref<CallingConvention> GetCdeclCallingConvention() const;

		/*! Get the stdcall CallingConvention

			\return The stdcall CallingConvention
		*/
		Ref<CallingConvention> GetStdcallCallingConvention() const;

		/*! Get the fastcall CallingConvention

			\return The fastcall Calling Convention
		*/
		Ref<CallingConvention> GetFastcallCallingConvention() const;

		/*! Get the list of registered calling conventions

			\return The list of registered calling conventions
		*/
		std::vector<Ref<CallingConvention>> GetCallingConventions() const;

		/*! Get the syscall calling convention

			\return The syscall CallingConvention
		*/
		Ref<CallingConvention> GetSystemCallConvention() const;

		/*! Register a Calling Convention

			\param cc Calling Convention to register
		*/
		void RegisterCallingConvention(CallingConvention* cc);

		/*! Set the default calling convention

			\param cc The new default CallingConvention
		*/
		void RegisterDefaultCallingConvention(CallingConvention* cc);

		/*! Set the cdecl calling convention

			\param cc The new cdecl CallingConvention
		*/
		void RegisterCdeclCallingConvention(CallingConvention* cc);

		/*! Set the stdcall calling convention

			\param cc The new stdcall CallingConvention
		*/
		void RegisterStdcallCallingConvention(CallingConvention* cc);

		/*! Set the fastcall calling convention

			\param cc The new fastcall calling convention
		*/
		void RegisterFastcallCallingConvention(CallingConvention* cc);

		/*! Set the syscall calling convention

			\param cc The new syscall calling convention
		*/
		void SetSystemCallConvention(CallingConvention* cc);

		Ref<Platform> GetRelatedPlatform(Architecture* arch);
		void AddRelatedPlatform(Architecture* arch, Platform* platform);
		Ref<Platform> GetAssociatedPlatformByAddress(uint64_t& addr);

		/*! Get the list of platform-specific types

			\return A map of Platform Type QualifiedNames and Ref<Type>s
		*/
		std::map<QualifiedName, Ref<Type>> GetTypes();

		/*! Get the list of platform-specific variable definitions

			\return A map of Platform Variable QualifiedNames and Ref<Type>s
		*/
		std::map<QualifiedName, Ref<Type>> GetVariables();

		/*! Get the list of platform-specific function definitions

			\return A map of Platform Function QualifiedNames and Ref<Type>s
		*/
		std::map<QualifiedName, Ref<Type>> GetFunctions();

		/*! System calls for this platform

			\return A list of system calls for this platform
		*/
		std::map<uint32_t, QualifiedNameAndType> GetSystemCalls();
		Ref<Type> GetTypeByName(const QualifiedName& name);
		Ref<Type> GetVariableByName(const QualifiedName& name);
		Ref<Type> GetFunctionByName(const QualifiedName& name, bool exactMatch = false);
		std::string GetSystemCallName(uint32_t n);
		Ref<Type> GetSystemCallType(uint32_t n);

		std::string GenerateAutoPlatformTypeId(const QualifiedName& name);
		Ref<NamedTypeReference> GenerateAutoPlatformTypeReference(
		    BNNamedTypeReferenceClass cls, const QualifiedName& name);
		std::string GetAutoPlatformTypeIdSource();

		/*! Parses the source string and any needed headers searching for them in
			the optional list of directories provided in ``includeDirs``.

		 	\note This API does not allow the source to rely on existing types that only exist in a specific view. Use BinaryView->ParseTypeString instead.

			\param source Source string to be parsed
			\param fileName Source Filename
			\param types map reference that Types will be copied into
			\param variables map reference that variables will be copied into
			\param functions map reference that functions will be copied into
			\param errors string reference that any errors will be copied into
			\param includeDirs optional list of directories to include for header searches
			\param autoTypeSource optional source of types if used for automatically generated types
			\return true on success, false otherwise
		*/
		bool ParseTypesFromSource(const std::string& source, const std::string& fileName,
		    std::map<QualifiedName, Ref<Type>>& types, std::map<QualifiedName, Ref<Type>>& variables,
		    std::map<QualifiedName, Ref<Type>>& functions, std::string& errors,
		    const std::vector<std::string>& includeDirs = std::vector<std::string>(),
		    const std::string& autoTypeSource = "");

		/*! Parses the source string and any needed headers searching for them in
			the optional list of directories provided in ``includeDirs``.

			\note This API does not allow the source to rely on existing types that only exist in a specific view. Use BinaryView->ParseTypeString instead.

			\param fileName Source Filename
			\param types map reference that Types will be copied into
			\param variables map reference that variables will be copied into
			\param functions map reference that functions will be copied into
			\param errors string reference that any errors will be copied into
			\param includeDirs optional list of directories to include for header searches
			\param autoTypeSource optional source of types if used for automatically generated types
			\return true on success, false otherwise
			\return
		*/
		bool ParseTypesFromSourceFile(const std::string& fileName, std::map<QualifiedName, Ref<Type>>& types,
		    std::map<QualifiedName, Ref<Type>>& variables, std::map<QualifiedName, Ref<Type>>& functions,
		    std::string& errors, const std::vector<std::string>& includeDirs = std::vector<std::string>(),
		    const std::string& autoTypeSource = "");
	};

	/*!
		\ingroup typeparser
	*/
	class TypeParser: public StaticCoreRefCountObject<BNTypeParser>
	{
		std::string m_nameForRegister;
	  protected:
		explicit TypeParser(const std::string& name);
		TypeParser(BNTypeParser* parser);

		static bool PreprocessSourceCallback(void* ctxt,
			const char* source, const char* fileName, BNPlatform* platform,
			const BNQualifiedNameTypeAndId* existingTypes, size_t existingTypeCount,
			const char* const* options, size_t optionCount,
			const char* const* includeDirs, size_t includeDirCount,
			char** output, BNTypeParserError** errors, size_t* errorCount
		);
		static bool ParseTypesFromSourceCallback(void* ctxt,
			const char* source, const char* fileName, BNPlatform* platform,
			const BNQualifiedNameTypeAndId* existingTypes, size_t existingTypeCount,
			const char* const* options, size_t optionCount,
			const char* const* includeDirs, size_t includeDirCount,
			const char* autoTypeSource, BNTypeParserResult* result,
			BNTypeParserError** errors, size_t* errorCount
		);
		static bool ParseTypeStringCallback(void* ctxt,
			const char* source, BNPlatform* platform,
			const BNQualifiedNameTypeAndId* existingTypes, size_t existingTypeCount,
			BNQualifiedNameAndType* result,
			BNTypeParserError** errors, size_t* errorCount
		);
		static void FreeStringCallback(void* ctxt, char* result);
		static void FreeResultCallback(void* ctxt, BNTypeParserResult* result);
		static void FreeErrorListCallback(void* ctxt, BNTypeParserError* errors, size_t errorCount);

	  public:
		static void Register(TypeParser* parser);
		static std::vector<Ref<TypeParser>> GetList();
		static Ref<TypeParser> GetByName(const std::string& name);
		static Ref<TypeParser> GetDefault();

		/*!
		    Preprocess a block of source, returning the source that would be parsed
		    \param source Source code to process
		    \param fileName Name of the file containing the source (does not need to exist on disk)
		    \param platform Platform to assume the source is relevant to
		    \param existingTypes Map of all existing types to use for parsing context
		    \param options String arguments to pass as options, e.g. command line arguments
		    \param includeDirs List of directories to include in the header search path
		    \param output Reference to a string into which the preprocessed source will be written
		    \param errors Reference to a list into which any parse errors will be written
		    \return True if preprocessing was successful
		*/
		virtual bool PreprocessSource(
			const std::string& source,
			const std::string& fileName,
			Ref<Platform> platform,
			const std::map<QualifiedName, TypeAndId>& existingTypes,
			const std::vector<std::string>& options,
			const std::vector<std::string>& includeDirs,
			std::string& output,
			std::vector<TypeParserError>& errors
		) = 0;

		/*!
		    Parse an entire block of source into types, variables, and functions
		    \param source Source code to parse
		    \param fileName Name of the file containing the source (optional: exists on disk)
		    \param platform Platform to assume the types are relevant to
		    \param existingTypes Map of all existing types to use for parsing context
		    \param options String arguments to pass as options, e.g. command line arguments
		    \param includeDirs List of directories to include in the header search path
		    \param autoTypeSource Optional source of types if used for automatically generated types
		    \param result Reference to structure into which the results will be written
		    \param errors Reference to a list into which any parse errors will be written
		    \return True if parsing was successful
		*/
		virtual bool ParseTypesFromSource(
			const std::string& source,
			const std::string& fileName,
			Ref<Platform> platform,
			const std::map<QualifiedName, TypeAndId>& existingTypes,
			const std::vector<std::string>& options,
			const std::vector<std::string>& includeDirs,
			const std::string& autoTypeSource,
			TypeParserResult& result,
			std::vector<TypeParserError>& errors
		) = 0;

		/*!
		    Parse a single type and name from a string containing their definition.
		    \param source Source code to parse
		    \param platform Platform to assume the types are relevant to
		    \param existingTypes Map of all existing types to use for parsing context
		    \param result Reference into which the resulting type and name will be written
		    \param errors Reference to a list into which any parse errors will be written
		    \return True if parsing was successful
		*/
		virtual bool ParseTypeString(
			const std::string& source,
			Ref<Platform> platform,
			const std::map<QualifiedName, TypeAndId>& existingTypes,
			QualifiedNameAndType& result,
			std::vector<TypeParserError>& errors
		) = 0;
	};

	/*!
		\ingroup typeparser
	*/
	class CoreTypeParser: public TypeParser
	{
	  public:
		CoreTypeParser(BNTypeParser* parser);
		virtual ~CoreTypeParser() {}

		virtual bool PreprocessSource(
			const std::string& source,
			const std::string& fileName,
			Ref<Platform> platform,
			const std::map<QualifiedName, TypeAndId>& existingTypes,
			const std::vector<std::string>& options,
			const std::vector<std::string>& includeDirs,
			std::string& output,
			std::vector<TypeParserError>& errors
		) override;

		virtual bool ParseTypesFromSource(
			const std::string& source,
			const std::string& fileName,
			Ref<Platform> platform,
			const std::map<QualifiedName, TypeAndId>& existingTypes,
			const std::vector<std::string>& options,
			const std::vector<std::string>& includeDirs,
			const std::string& autoTypeSource,
			TypeParserResult& result,
			std::vector<TypeParserError>& errors
		) override;

		virtual bool ParseTypeString(
			const std::string& source,
			Ref<Platform> platform,
			const std::map<QualifiedName, TypeAndId>& existingTypes,
			QualifiedNameAndType& result,
			std::vector<TypeParserError>& errors
		) override;
	};

	/*!
		\ingroup typeprinter
	*/
	class TypePrinter: public StaticCoreRefCountObject<BNTypePrinter>
	{
		std::string m_nameForRegister;
	  protected:
		explicit TypePrinter(const std::string& name);
		TypePrinter(BNTypePrinter* printer);

		static bool GetTypeTokensCallback(void* ctxt, BNType* type, BNPlatform* platform,
			BNQualifiedName* name, uint8_t baseConfidence, BNTokenEscapingType escaping,
			BNInstructionTextToken** result, size_t* resultCount);
		static bool GetTypeTokensBeforeNameCallback(void* ctxt, BNType* type,
			BNPlatform* platform, uint8_t baseConfidence, BNType* parentType,
			BNTokenEscapingType escaping, BNInstructionTextToken** result,
			size_t* resultCount);
		static bool GetTypeTokensAfterNameCallback(void* ctxt, BNType* type,
			BNPlatform* platform, uint8_t baseConfidence, BNType* parentType,
			BNTokenEscapingType escaping, BNInstructionTextToken** result,
			size_t* resultCount);
		static bool GetTypeStringCallback(void* ctxt, BNType* type, BNPlatform* platform,
			BNQualifiedName* name, BNTokenEscapingType escaping, char** result);
		static bool GetTypeStringBeforeNameCallback(void* ctxt, BNType* type,
			BNPlatform* platform, BNTokenEscapingType escaping, char** result);
		static bool GetTypeStringAfterNameCallback(void* ctxt, BNType* type,
			BNPlatform* platform, BNTokenEscapingType escaping, char** result);
		static bool GetTypeLinesCallback(void* ctxt, BNType* type, BNBinaryView* data,
			BNQualifiedName* name, int lineWidth, bool collapsed,
			BNTokenEscapingType escaping, BNTypeDefinitionLine** result, size_t* resultCount);
		static void FreeTokensCallback(void* ctxt, BNInstructionTextToken* tokens, size_t count);
		static void FreeStringCallback(void* ctxt, char* string);
		static void FreeLinesCallback(void* ctxt, BNTypeDefinitionLine* lines, size_t count);

	  public:
		static void Register(TypePrinter* printer);
		static std::vector<Ref<TypePrinter>> GetList();
		static Ref<TypePrinter> GetByName(const std::string& name);
		static Ref<TypePrinter> GetDefault();

		/*!
		    Generate a single-line text representation of a type
		    \param type Type to print
		    \param platform Platform responsible for this type
		    \param name Name of the type
		    \param baseConfidence Confidence to use for tokens created for this type
		    \param escaping Style of escaping literals which may not be parsable
		    \return List of text tokens representing the type
		*/
		virtual std::vector<InstructionTextToken> GetTypeTokens(
			Ref<Type> type,
			Ref<Platform> platform,
			const QualifiedName& name,
			uint8_t baseConfidence = BN_FULL_CONFIDENCE,
			BNTokenEscapingType escaping = NoTokenEscapingType
		);
		/*!
		    In a single-line text representation of a type, generate the tokens that should
		    be printed before the type's name.

		    \param type Type to print
		    \param platform Platform responsible for this type
		    \param baseConfidence Confidence to use for tokens created for this type
		    \param parentType Type of the parent of this type, or nullptr
		    \param escaping Style of escaping literals which may not be parsable
		    \return List of text tokens representing the type
		*/
		virtual std::vector<InstructionTextToken> GetTypeTokensBeforeName(
			Ref<Type> type,
			Ref<Platform> platform,
			uint8_t baseConfidence = BN_FULL_CONFIDENCE,
			Ref<Type> parentType = nullptr,
			BNTokenEscapingType escaping = NoTokenEscapingType
		) = 0;
		/*!
		    In a single-line text representation of a type, generate the tokens that should
		    be printed after the type's name.

		    \param type Type to print
		    \param platform Platform responsible for this type
		    \param baseConfidence Confidence to use for tokens created for this type
		    \param parentType Type of the parent of this type, or nullptr
		    \param escaping Style of escaping literals which may not be parsable
		    \return List of text tokens representing the type
		*/
		virtual std::vector<InstructionTextToken> GetTypeTokensAfterName(
			Ref<Type> type,
			Ref<Platform> platform,
			uint8_t baseConfidence = BN_FULL_CONFIDENCE,
			Ref<Type> parentType = nullptr,
			BNTokenEscapingType escaping = NoTokenEscapingType
		) = 0;

		/*!
		    Generate a single-line text representation of a type
		    \param type Type to print
		    \param platform Platform responsible for this type
		    \param name Name of the type
		    \param escaping Style of escaping literals which may not be parsable
		    \return String representing the type
		*/
		virtual std::string GetTypeString(
			Ref<Type> type,
			Ref<Platform> platform,
			const QualifiedName& name,
			BNTokenEscapingType escaping = NoTokenEscapingType
		);
		/*!
		    In a single-line text representation of a type, generate the string that should
		    be printed before the type's name.

		    \param type Type to print
		    \param platform Platform responsible for this type
		    \param escaping Style of escaping literals which may not be parsable
		    \return String representing the type
		*/
		virtual std::string GetTypeStringBeforeName(
			Ref<Type> type,
			Ref<Platform> platform,
			BNTokenEscapingType escaping = NoTokenEscapingType
		);
		/*!
		    In a single-line text representation of a type, generate the string that should
		    be printed after the type's name.

		    \param type Type to print
		    \param platform Platform responsible for this type
		    \param escaping Style of escaping literals which may not be parsable
		    \return String representing the type
		*/
		virtual std::string GetTypeStringAfterName(
			Ref<Type> type,
			Ref<Platform> platform,
			BNTokenEscapingType escaping = NoTokenEscapingType
		);

		/*!
		    Generate a multi-line representation of a type
		    \param type Type to print
		    \param data Binary View in which the type is defined
		    \param name Name of the type
		    \param lineWidth Maximum width of lines, in characters
		    \param collapsed Whether to collapse structure/enum blocks
		    \param escaping Style of escaping literals which may not be parsable
		    \return List of type definition lines
		*/
		virtual std::vector<TypeDefinitionLine> GetTypeLines(
			Ref<Type> type,
			Ref<BinaryView> data,
			const QualifiedName& name,
			int lineWidth = 80,
			bool collapsed = false,
			BNTokenEscapingType escaping = NoTokenEscapingType
		) = 0;
	};

	/*!
		\ingroup typeprinter
	*/
	class CoreTypePrinter: public TypePrinter
	{
	  public:
		CoreTypePrinter(BNTypePrinter* printer);
		virtual ~CoreTypePrinter() {}

		virtual std::vector<InstructionTextToken> GetTypeTokens(Ref<Type> type,
			Ref<Platform> platform, const QualifiedName& name,
			uint8_t baseConfidence, BNTokenEscapingType escaping) override;
		virtual std::vector<InstructionTextToken> GetTypeTokensBeforeName(Ref<Type> type,
			Ref<Platform> platform, uint8_t baseConfidence,
			Ref<Type> parentType, BNTokenEscapingType escaping) override;
		virtual std::vector<InstructionTextToken> GetTypeTokensAfterName(Ref<Type> type,
			Ref<Platform> platform, uint8_t baseConfidence,
			Ref<Type> parentType, BNTokenEscapingType escaping) override;
		virtual std::string GetTypeString(Ref<Type> type, Ref<Platform> platform,
			const QualifiedName& name, BNTokenEscapingType escaping) override;
		virtual std::string GetTypeStringBeforeName(Ref<Type> type, Ref<Platform> platform,
			BNTokenEscapingType escaping) override;
		virtual std::string GetTypeStringAfterName(Ref<Type> type, Ref<Platform> platform,
			BNTokenEscapingType escaping) override;
		virtual std::vector<TypeDefinitionLine> GetTypeLines(Ref<Type> type,
			Ref<BinaryView> data, const QualifiedName& name, int lineWidth,
			bool collapsed, BNTokenEscapingType escaping) override;
	};

	// DownloadProvider
	class DownloadProvider;

	/*!
		\ingroup downloadprovider
	*/
	class DownloadInstance :
	    public CoreRefCountObject<BNDownloadInstance, BNNewDownloadInstanceReference, BNFreeDownloadInstance>
	{
	  public:
		struct Response
		{
			uint16_t statusCode;
			std::unordered_map<std::string, std::string> headers;
		};

	  protected:
		DownloadInstance(DownloadProvider* provider);
		DownloadInstance(BNDownloadInstance* instance);

		static void DestroyInstanceCallback(void* ctxt);
		static int PerformRequestCallback(void* ctxt, const char* url);
		static int PerformCustomRequestCallback(void* ctxt, const char* method, const char* url, uint64_t headerCount,
		    const char* const* headerKeys, const char* const* headerValues, BNDownloadInstanceResponse** response);
		static void PerformFreeResponse(void* ctxt, BNDownloadInstanceResponse* response);
		/*!
		    Cleanup any resources created by the instance
		*/
		virtual void DestroyInstance();
		/*!
		    Virtual method to synchronously perform a GET request to a url, overridden by a subclass
		    \param url Full url to request
		    \return Zero on successful request, negative on failed request
		*/
		virtual int PerformRequest(const std::string& url) = 0;
		/*!
		    Virtual method to synchronously perform a request to a url, overridden by a subclass
		    \param method Request method e.g. GET
		    \param url Full url to request
		    \param headers HTTP headers as keys/values
		    \param response Structure into which the response status code and headers should be stored
		    \return Zero on successful request, negative on failed request
		*/
		virtual int PerformCustomRequest(const std::string& method, const std::string& url,
		    const std::unordered_map<std::string, std::string>& headers, Response& response) = 0;

		int64_t ReadDataCallback(uint8_t* data, uint64_t len);
		uint64_t WriteDataCallback(uint8_t* data, uint64_t len);
		bool NotifyProgressCallback(uint64_t progress, uint64_t total);
		void SetError(const std::string& error);

	  public:
		/*!
		    Send a GET request to a url, synchronously
		    \param url Full url to request
		    \param callbacks Structure with callback functions for output data
		    \return Zero on successful request, negative on failed request
		*/
		int PerformRequest(const std::string& url, BNDownloadInstanceOutputCallbacks* callbacks);
		/*!
		    Send a request to a url, synchronously
		    \param method Request method e.g. GET
		    \param url Full url to request
		    \param headers HTTP headers as keys/values
		    \param response Structure into which the response status code and headers are stored
		    \param callbacks Structure with callback functions for input and output data
		    \return Zero on successful request, negative on failed request
		*/
		int PerformCustomRequest(const std::string& method, const std::string& url,
		    const std::unordered_map<std::string, std::string>& headers, Response& response,
		    BNDownloadInstanceInputOutputCallbacks* callbacks);
		/*!
		    Retrieve the error from the last request sent by this instance
		*/
		std::string GetError() const;
	};

	class CoreDownloadInstance : public DownloadInstance
	{
	  public:
		CoreDownloadInstance(BNDownloadInstance* instance);
		virtual ~CoreDownloadInstance() {};

		virtual int PerformRequest(const std::string& url) override;
		virtual int PerformCustomRequest(const std::string& method, const std::string& url,
		    const std::unordered_map<std::string, std::string>& headers, DownloadInstance::Response& response) override;
	};

	/*!
		\ingroup downloadprovider
	*/
	class DownloadProvider : public StaticCoreRefCountObject<BNDownloadProvider>
	{
		std::string m_nameForRegister;

	  protected:
		DownloadProvider(const std::string& name);
		DownloadProvider(BNDownloadProvider* provider);

		static BNDownloadInstance* CreateInstanceCallback(void* ctxt);

	  public:
		virtual Ref<DownloadInstance> CreateNewInstance() = 0;

		static std::vector<Ref<DownloadProvider>> GetList();
		static Ref<DownloadProvider> GetByName(const std::string& name);
		static void Register(DownloadProvider* provider);
	};

	class CoreDownloadProvider : public DownloadProvider
	{
	  public:
		CoreDownloadProvider(BNDownloadProvider* provider);
		virtual Ref<DownloadInstance> CreateNewInstance() override;
	};

	// WebsocketProvider
	class WebsocketProvider;

	/*!
		\ingroup websocketprovider
	*/
	class WebsocketClient :
	    public CoreRefCountObject<BNWebsocketClient, BNNewWebsocketClientReference, BNFreeWebsocketClient>
	{
	  protected:
		WebsocketClient(WebsocketProvider* provider);
		WebsocketClient(BNWebsocketClient* instance);

		static void DestroyClientCallback(void* ctxt);
		static bool ConnectCallback(void* ctxt, const char* host, uint64_t headerCount, const char* const* headerKeys,
		    const char* const* headerValues);
		static bool WriteCallback(const uint8_t* data, uint64_t len, void* ctxt);
		static bool DisconnectCallback(void* ctxt);
		static void ErrorCallback(const char* msg, void* ctxt);
		bool ReadData(uint8_t* data, uint64_t len);

		/*!
		    Cleanup any resources created by the client
		*/
		virtual void DestroyClient();
		/*!
		    Virtual method for performing the connection, overridden by a subclass.
		    \param host Full url with scheme, domain, optionally port, and path
		    \param headers HTTP header keys and values
		    \return True if the connection has started, but not necessarily if it succeeded
		*/
		virtual bool Connect(const std::string& host, const std::unordered_map<std::string, std::string>& headers) = 0;

	  public:
		/*!
		    Connect to a given url, asynchronously. The connection will be run in a separate thread managed by the
		   websocket provider.

		    Callbacks will be called **on the thread of the connection**, so be sure to ExecuteOnMainThread any
		   long-running or gui operations in the callbacks.

		    If the connection succeeds, connectedCallback will be called. On normal termination, disconnectedCallback
		   will be called. If the connection succeeds, but later fails, disconnectedCallback will not be called, and
		   errorCallback will be called instead. If the connection fails, neither connectedCallback nor
		   disconnectedCallback will be called, and errorCallback will be called instead.

		    If connectedCallback or readCallback return false, the connection will be aborted.

		    \param host Full url with scheme, domain, optionally port, and path
		    \param headers HTTP header keys and values
		    \param callbacks Structure with callbacks for various websocket events
		    \return True if the connection has started, but not necessarily if it succeeded
		*/
		bool Connect(const std::string& host, const std::unordered_map<std::string, std::string>& headers,
		    BNWebsocketClientOutputCallbacks* callbacks);

		/*!
		    Write some data to the websocket
		    \param data Data to write
		    \return True if successful
		*/
		virtual bool Write(const std::vector<uint8_t>& data) = 0;
		/*!
		    Disconnect the websocket
		    \return True if successful
		*/
		virtual bool Disconnect() = 0;
	};

	/*!
		\ingroup websocketprovider
	*/
	class CoreWebsocketClient : public WebsocketClient
	{
	  public:
		CoreWebsocketClient(BNWebsocketClient* instance);
		virtual ~CoreWebsocketClient() {};

		virtual bool Connect(
		    const std::string& host, const std::unordered_map<std::string, std::string>& headers) override;
		virtual bool Write(const std::vector<uint8_t>& data) override;
		virtual bool Disconnect() override;
	};

	/*!
		\ingroup websocketprovider
	*/
	class WebsocketProvider : public StaticCoreRefCountObject<BNWebsocketProvider>
	{
		std::string m_nameForRegister;

	  protected:
		WebsocketProvider(const std::string& name);
		WebsocketProvider(BNWebsocketProvider* provider);

		static BNWebsocketClient* CreateClientCallback(void* ctxt);

	  public:
		virtual Ref<WebsocketClient> CreateNewClient() = 0;

		static std::vector<Ref<WebsocketProvider>> GetList();
		static Ref<WebsocketProvider> GetByName(const std::string& name);
		static void Register(WebsocketProvider* provider);
	};

	class CoreWebsocketProvider : public WebsocketProvider
	{
	  public:
		CoreWebsocketProvider(BNWebsocketProvider* provider);
		virtual Ref<WebsocketClient> CreateNewClient() override;
	};

	// Scripting Provider
	/*!
		\ingroup scriptingprovider
	*/
	class ScriptingOutputListener
	{
		BNScriptingOutputListener m_callbacks;

		static void OutputCallback(void* ctxt, const char* text);
		static void ErrorCallback(void* ctxt, const char* text);
		static void InputReadyStateChangedCallback(void* ctxt, BNScriptingProviderInputReadyState state);

	  public:
		ScriptingOutputListener();
		BNScriptingOutputListener& GetCallbacks() { return m_callbacks; }

		virtual void NotifyOutput(const std::string& text);
		virtual void NotifyError(const std::string& text);
		virtual void NotifyInputReadyStateChanged(BNScriptingProviderInputReadyState state);
	};

	class ScriptingProvider;

	/*!
		\ingroup scriptingprovider
	*/
	class ScriptingInstance :
	    public CoreRefCountObject<BNScriptingInstance, BNNewScriptingInstanceReference, BNFreeScriptingInstance>
	{
	  protected:
		ScriptingInstance(ScriptingProvider* provider);
		ScriptingInstance(BNScriptingInstance* instance);

		static void DestroyInstanceCallback(void* ctxt);
		static BNScriptingProviderExecuteResult ExecuteScriptInputCallback(void* ctxt, const char* input);
		static BNScriptingProviderExecuteResult ExecuteScriptFromFilenameCallback(void *ctxt, const char* filename);
		static void CancelScriptInputCallback(void* ctxt);
		static void SetCurrentBinaryViewCallback(void* ctxt, BNBinaryView* view);
		static void SetCurrentFunctionCallback(void* ctxt, BNFunction* func);
		static void SetCurrentBasicBlockCallback(void* ctxt, BNBasicBlock* block);
		static void SetCurrentAddressCallback(void* ctxt, uint64_t addr);
		static void SetCurrentSelectionCallback(void* ctxt, uint64_t begin, uint64_t end);
		static char* CompleteInputCallback(void* ctxt, const char* text, uint64_t state);
		static void StopCallback(void* ctxt);

		virtual void DestroyInstance();

	  public:
		virtual BNScriptingProviderExecuteResult ExecuteScriptInput(const std::string& input) = 0;
		virtual BNScriptingProviderExecuteResult ExecuteScriptInputFromFilename(const std::string& filename) = 0;
		virtual void CancelScriptInput();
		virtual void SetCurrentBinaryView(BinaryView* view);
		virtual void SetCurrentFunction(Function* func);
		virtual void SetCurrentBasicBlock(BasicBlock* block);
		virtual void SetCurrentAddress(uint64_t addr);
		virtual void SetCurrentSelection(uint64_t begin, uint64_t end);
		virtual std::string CompleteInput(const std::string& text, uint64_t state);
		virtual void Stop();

		void Output(const std::string& text);
		void Error(const std::string& text);
		void InputReadyStateChanged(BNScriptingProviderInputReadyState state);
		BNScriptingProviderInputReadyState GetInputReadyState();

		void RegisterOutputListener(ScriptingOutputListener* listener);
		void UnregisterOutputListener(ScriptingOutputListener* listener);

		std::string GetDelimiters();
		void SetDelimiters(const std::string& delimiters);
	};

	/*!
		\ingroup scriptingprovider
	*/
	class CoreScriptingInstance : public ScriptingInstance
	{
	  public:
		CoreScriptingInstance(BNScriptingInstance* instance);
		virtual ~CoreScriptingInstance() {};

		virtual BNScriptingProviderExecuteResult ExecuteScriptInput(const std::string& input) override;
		virtual BNScriptingProviderExecuteResult ExecuteScriptInputFromFilename(const std::string& filename) override;
		virtual void CancelScriptInput() override;
		virtual void SetCurrentBinaryView(BinaryView* view) override;
		virtual void SetCurrentFunction(Function* func) override;
		virtual void SetCurrentBasicBlock(BasicBlock* block) override;
		virtual void SetCurrentAddress(uint64_t addr) override;
		virtual void SetCurrentSelection(uint64_t begin, uint64_t end) override;
		virtual std::string CompleteInput(const std::string& text, uint64_t state) override;
		virtual void Stop() override;
	};

	/*!
		\ingroup scriptingprovider
	*/
	class ScriptingProvider : public StaticCoreRefCountObject<BNScriptingProvider>
	{
		std::string m_nameForRegister;
		std::string m_apiNameForRegister;

	  protected:
		ScriptingProvider(const std::string& name, const std::string& apiName);
		ScriptingProvider(BNScriptingProvider* provider);

		static BNScriptingInstance* CreateInstanceCallback(void* ctxt);
		static bool LoadModuleCallback(void* ctxt, const char* repository, const char* module, bool force);
		static bool InstallModulesCallback(void* ctxt, const char* modules);

	  public:
		virtual Ref<ScriptingInstance> CreateNewInstance() = 0;
		virtual bool LoadModule(const std::string& repository, const std::string& module, bool force) = 0;
		virtual bool InstallModules(const std::string& modules) = 0;

		std::string GetName();
		std::string GetAPIName();

		static std::vector<Ref<ScriptingProvider>> GetList();
		static Ref<ScriptingProvider> GetByName(const std::string& name);
		static Ref<ScriptingProvider> GetByAPIName(const std::string& apiName);
		static void Register(ScriptingProvider* provider);
	};

	class CoreScriptingProvider : public ScriptingProvider
	{
	  public:
		CoreScriptingProvider(BNScriptingProvider* provider);
		virtual Ref<ScriptingInstance> CreateNewInstance() override;
		virtual bool LoadModule(const std::string& repository, const std::string& module, bool force) override;
		virtual bool InstallModules(const std::string& modules) override;
	};

	/*!
		\ingroup plugin
	*/
	class MainThreadAction :
	    public CoreRefCountObject<BNMainThreadAction, BNNewMainThreadActionReference, BNFreeMainThreadAction>
	{
	  public:
		MainThreadAction(BNMainThreadAction* action);
		void Execute();
		bool IsDone() const;
		void Wait();
	};

	/*!
		\ingroup plugin
	*/
	class MainThreadActionHandler
	{
	  public:
		virtual void AddMainThreadAction(MainThreadAction* action) = 0;
	};

	/*!
		\ingroup plugin
	*/
	class BackgroundTask :
	    public CoreRefCountObject<BNBackgroundTask, BNNewBackgroundTaskReference, BNFreeBackgroundTask>
	{
	  public:
		BackgroundTask(BNBackgroundTask* task);
		BackgroundTask(const std::string& initialText, bool canCancel);

		bool CanCancel() const;
		bool IsCancelled() const;
		bool IsFinished() const;
		std::string GetProgressText() const;

		void Cancel();
		void Finish();
		void SetProgressText(const std::string& text);

		static std::vector<Ref<BackgroundTask>> GetRunningTasks();
	};

	/*!
		\ingroup interaction
	*/
	struct FormInputField
	{
		BNFormInputFieldType type;
		std::string prompt;
		Ref<BinaryView> view;              // For AddressFormField
		uint64_t currentAddress;           // For AddressFormField
		std::vector<std::string> choices;  // For ChoiceFormField
		std::string ext;                   // For OpenFileNameFormField, SaveFileNameFormField
		std::string defaultName;           // For SaveFileNameFormField
		int64_t intResult;
		uint64_t addressResult;
		std::string stringResult;
		size_t indexResult;
		bool hasDefault;
		int64_t intDefault;
		uint64_t addressDefault;
		std::string stringDefault;
		size_t indexDefault;

		static FormInputField Label(const std::string& text);
		static FormInputField Separator();
		static FormInputField TextLine(const std::string& prompt);
		static FormInputField MultilineText(const std::string& prompt);
		static FormInputField Integer(const std::string& prompt);
		static FormInputField Address(
		    const std::string& prompt, BinaryView* view = nullptr, uint64_t currentAddress = 0);
		static FormInputField Choice(const std::string& prompt, const std::vector<std::string>& choices);
		static FormInputField OpenFileName(const std::string& prompt, const std::string& ext);
		static FormInputField SaveFileName(
		    const std::string& prompt, const std::string& ext, const std::string& defaultName = "");
		static FormInputField DirectoryName(const std::string& prompt, const std::string& defaultName = "");
	};

	/*!

		\ingroup coreapi
	*/
	class ReportCollection :
	    public CoreRefCountObject<BNReportCollection, BNNewReportCollectionReference, BNFreeReportCollection>
	{
	  public:
		ReportCollection();
		ReportCollection(BNReportCollection* reports);

		size_t GetCount() const;
		BNReportType GetType(size_t i) const;
		Ref<BinaryView> GetView(size_t i) const;
		std::string GetTitle(size_t i) const;
		std::string GetContents(size_t i) const;
		std::string GetPlainText(size_t i) const;
		Ref<FlowGraph> GetFlowGraph(size_t i) const;

		void AddPlainTextReport(Ref<BinaryView> view, const std::string& title, const std::string& contents);
		void AddMarkdownReport(Ref<BinaryView> view, const std::string& title, const std::string& contents,
		    const std::string& plainText = "");
		void AddHTMLReport(Ref<BinaryView> view, const std::string& title, const std::string& contents,
		    const std::string& plainText = "");
		void AddGraphReport(Ref<BinaryView> view, const std::string& title, Ref<FlowGraph> graph);

		void UpdateFlowGraph(size_t i, Ref<FlowGraph> graph);
	};

	/*!
		\ingroup interaction
	*/
	class InteractionHandler
	{
	  public:
		virtual void ShowPlainTextReport(
		    Ref<BinaryView> view, const std::string& title, const std::string& contents) = 0;
		virtual void ShowMarkdownReport(
		    Ref<BinaryView> view, const std::string& title, const std::string& contents, const std::string& plainText);
		virtual void ShowHTMLReport(
		    Ref<BinaryView> view, const std::string& title, const std::string& contents, const std::string& plainText);
		virtual void ShowGraphReport(Ref<BinaryView> view, const std::string& title, Ref<FlowGraph> graph);
		virtual void ShowReportCollection(const std::string& title, Ref<ReportCollection> reports);

		virtual bool GetTextLineInput(std::string& result, const std::string& prompt, const std::string& title) = 0;
		virtual bool GetIntegerInput(int64_t& result, const std::string& prompt, const std::string& title);
		virtual bool GetAddressInput(uint64_t& result, const std::string& prompt, const std::string& title,
		    Ref<BinaryView> view, uint64_t currentAddr);
		virtual bool GetChoiceInput(size_t& idx, const std::string& prompt, const std::string& title,
		    const std::vector<std::string>& choices) = 0;
		virtual bool GetOpenFileNameInput(std::string& result, const std::string& prompt, const std::string& ext = "");
		virtual bool GetSaveFileNameInput(std::string& result, const std::string& prompt, const std::string& ext = "",
		    const std::string& defaultName = "");
		virtual bool GetDirectoryNameInput(
		    std::string& result, const std::string& prompt, const std::string& defaultName = "");
		virtual bool GetFormInput(std::vector<FormInputField>& fields, const std::string& title) = 0;

		virtual BNMessageBoxButtonResult ShowMessageBox(const std::string& title, const std::string& text,
		    BNMessageBoxButtonSet buttons = OKButtonSet, BNMessageBoxIcon icon = InformationIcon) = 0;
		virtual bool OpenUrl(const std::string& url) = 0;
		virtual bool RunProgressDialog(const std::string& title, bool canCancel, std::function<void(std::function<bool(size_t, size_t)> progress)> task) = 0;
	};

	typedef BNPluginOrigin PluginOrigin;
	typedef BNPluginStatus PluginStatus;
	typedef BNPluginType PluginType;

	/*!
		\ingroup pluginmanager
	*/
	class RepoPlugin : public CoreRefCountObject<BNRepoPlugin, BNNewPluginReference, BNFreePlugin>
	{
	  public:
		RepoPlugin(BNRepoPlugin* plugin);
		PluginStatus GetPluginStatus() const;
		std::vector<std::string> GetApis() const;
		std::vector<std::string> GetInstallPlatforms() const;
		std::string GetPath() const;
		std::string GetSubdir() const;
		std::string GetDependencies() const;
		std::string GetPluginDirectory() const;
		std::string GetAuthor() const;
		std::string GetDescription() const;
		std::string GetLicense() const;
		std::string GetLicenseText() const;
		std::string GetLongdescription() const;
		std::string GetName() const;
		std::vector<PluginType> GetPluginTypes() const;
		std::string GetPackageUrl() const;
		std::string GetProjectUrl() const;
		std::string GetAuthorUrl() const;
		std::string GetVersion() const;
		std::string GetCommit() const;
		std::string GetRepository() const;
		std::string GetProjectData();
		std::string GetInstallInstructions(const std::string& platform) const;
		uint64_t GetMinimumVersion() const;
		uint64_t GetLastUpdate();
		bool IsBeingDeleted() const;
		bool IsBeingUpdated() const;
		bool IsInstalled() const;
		bool IsEnabled() const;
		bool IsRunning() const;
		bool IsUpdatePending() const;
		bool IsDisablePending() const;
		bool IsDeletePending() const;
		bool IsUpdateAvailable() const;
		bool AreDependenciesBeingInstalled() const;

		bool Uninstall();
		bool Install();
		bool InstallDependencies();
		// `force` ignores optional checks for platform/api compliance
		bool Enable(bool force);
		bool Disable();
		bool Update();
	};

	/*!
		\ingroup pluginmanager
	*/
	class Repository : public CoreRefCountObject<BNRepository, BNNewRepositoryReference, BNFreeRepository>
	{
	  public:
		Repository(BNRepository* repository);
		std::string GetUrl() const;
		std::string GetRepoPath() const;
		std::string GetLocalReference() const;
		std::string GetRemoteReference() const;
		std::vector<Ref<RepoPlugin>> GetPlugins() const;
		std::string GetPluginDirectory() const;
		Ref<RepoPlugin> GetPluginByPath(const std::string& pluginPath);
		std::string GetFullPath() const;
	};

	/*!
		\ingroup pluginmanager
	*/
	class RepositoryManager :
	    public CoreRefCountObject<BNRepositoryManager, BNNewRepositoryManagerReference, BNFreeRepositoryManager>
	{
	  public:
		RepositoryManager(const std::string& enabledPluginsPath);
		RepositoryManager(BNRepositoryManager* repoManager);
		RepositoryManager();
		bool CheckForUpdates();
		std::vector<Ref<Repository>> GetRepositories();
		Ref<Repository> GetRepositoryByPath(const std::string& repoName);
		bool AddRepository(const std::string& url,  // URL to raw plugins.json file
		    const std::string& repoPath);           // Relative path within the repositories directory
		Ref<Repository> GetDefaultRepository();
	};

	/*! \c Settings provides a way to define and access settings in a hierarchical fashion. The value of a setting can
		be defined for each hierarchical level, where each level overrides the preceding level. The backing-store for setting
		values at each level is also configurable. This allows for ephemeral or platform-independent persistent settings storage
		for components within Binary Ninja or consumers of the Binary Ninja API.

		Each \c Settings instance has an \c instanceId which identifies a schema. The schema defines the settings contents
		and the way in which settings are retrieved and manipulated. A new \c Settings instance defaults to using a value of <em><tt>default</tt></em>
		for the \c instanceId . The <em><tt>default</tt></em> settings schema defines all of the settings available for the active Binary Ninja components
		which include at a minimum, the settings defined by the Binary Ninja core. The <em><tt>default</tt></em> schema may additionally define settings
		for the UI and/or installed plugins. Extending existing schemas, or defining new ones is accomplished by calling \c RegisterGroup()
		and \c RegisterSetting() methods, or by deserializing an existing schema with \c DeserializeSchema() .

		\note All settings in the <em><tt>default</tt></em> settings schema are rendered with UI elements in the Settings View of Binary Ninja UI.

		Allowing setting overrides is an important feature and Binary Ninja accomplishes this by allowing one to override a setting at various
		levels. The levels and their associated storage are shown in the following table. Default setting values are optional, and if specified,
		saved in the schema itself.

			================= ========================== ============== ==============================================
			Setting Level     Settings Scope             Preference     Storage
			================= ========================== ============== ==============================================
			Default           SettingsDefaultScope       Lowest         Settings Schema
			User              SettingsUserScope          -              <User Directory>/settings.json
			Project           SettingsProjectScope       -              <Project Directory>/.binaryninja/settings.json
			Resource          SettingsResourceScope      Highest        Raw BinaryView (Storage in BNDB)
			================= ========================== ============== ==============================================

		Settings are identified by a key, which is a string in the form of <b><tt><group>.<name></tt></b> or <b><tt><group>.<subGroup>.<name></tt></b> . Groups provide
		a simple way to categorize settings. Sub-groups are optional and multiple sub-groups are allowed. When defining a settings group, the
		\c RegisterGroup method allows for specifying a UI friendly title for use in the Binary Ninja UI. Defining a new setting requires a
		unique setting key and a JSON string of property, value pairs. The following table describes the available properties and values.

			==================   ======================================   ==================   ========   =======================================================================
			Property             JSON Data Type                           Prerequisite         Optional   {Allowed Values} and Notes
			==================   ======================================   ==================   ========   =======================================================================
			"title"              string                                   None                 No         Concise Setting Title
			"type"               string                                   None                 No         {"array", "boolean", "number", "string"}
			"elementType"        string                                   "type" is "array"    No         {"string"}
			"enum"               array : {string}                         "type" is "array"    Yes        Enumeration definitions
			"enumDescriptions"   array : {string}                         "type" is "array"    Yes        Enumeration descriptions that match "enum" array
			"minValue"           number                                   "type" is "number"   Yes        Specify 0 to infer unsigned (default is signed)
			"maxValue"           number                                   "type" is "number"   Yes        Values less than or equal to INT_MAX result in a QSpinBox UI element
			"precision"          number                                   "type" is "number"   Yes        Specify precision for a QDoubleSpinBox
			"default"            {array, boolean, number, string, null}   None                 Yes        Specify optimal default value
			"aliases"            array : {string}                         None                 Yes        Array of deprecated setting key(s)
			"description"        string                                   None                 No         Detailed setting description
			"ignore"             array : {string}                         None                 Yes        {"SettingsUserScope", "SettingsProjectScope", "SettingsResourceScope"}
			"message"            string                                   None                 Yes        An optional message with additional emphasis
			"readOnly"           bool                                     None                 Yes        Only enforced by UI elements
			"optional"           bool                                     None                 Yes        Indicates setting can be null
			"requiresRestart     bool                                     None                 Yes        Enable restart notification in the UI upon change
			==================   ======================================   ==================   ========   =======================================================================

		\note In order to facilitate deterministic analysis results, settings from the <em><tt>default</tt></em> schema that impact analysis are serialized
		from Default, User, and Project scope into Resource scope during initial BinaryView analysis. This allows an analysis database to be opened
		at a later time with the same settings, regardless if Default, User, or Project settings have been modified.

		\note Settings that do not impact analysis (e.g. many UI settings) should use the \e "ignore" property to exclude
			\e "SettingsProjectScope" and \e "SettingsResourceScope" from the applicable scopes for the setting.

		<b>Example analysis plugin setting:</b>
	 	\code{.cpp}
		auto settings = Settings::Instance()

	 	settings->RegisterGroup("myPlugin", "My Plugin")

		settings->RegisterSetting("myPlugin.enablePreAnalysis",
			R"~({
			"title": "My Pre-Analysis Plugin",
			"type": "boolean",
			"default": false,
			"description": "Enable extra analysis before core analysis.",
			"ignore": ["SettingsProjectScope", "SettingsResourceScope"]
			})~");

	 	Json::Value options(Json::objectValue);
		options["myPlugin.enablePreAnalysis"] = Json::Value(true);
		Ref<BinaryView> bv = OpenView("/bin/ls", true, {}, options);

		Settings::Instance()->Get<bool>("myPlugin.enablePreAnalysis"); // false
	    Settings::Instance()->Get<bool>("myPlugin.enablePreAnalysis", bv); // true
		\endcode

	 	<b>Getting a settings value:</b>
	 	\code{.cpp}
	    bool excludeUnreferencedStrings = Settings::Instance()->Get<bool>("ui.stringView.excludeUnreferencedStrings", bv);
	    \endcode

	    \ingroup settings
	*/
	class Settings : public CoreRefCountObject<BNSettings, BNNewSettingsReference, BNFreeSettings>
	{
		std::string m_instanceId;

		Settings() = delete;
		Settings(const std::string& m_instanceId);

	  public:
		Settings(BNSettings* settings);
		static Ref<Settings> Instance(const std::string& schemaId = "");
		virtual ~Settings() {}

		/*! Sets the resource identifier for this \c Settings instance. When accessing setting values at the
			\c SettingsResourceScope level, the resource identifier is passed along through the backing store interface.

			\note Currently the only available backing store for \c SettingsResourceScope is a \c BinaryView object. In the context
			of a \c BinaryView the resource identifier is the \c BinaryViewType name. All settings for this type of backing store
			are saved in the \e 'Raw' \c BinaryViewType . This enables the configuration of setting values such that they are available
			during \c BinaryView creation and initialization.

			\param resourceId a unique identifier
		*/
		void SetResourceId(const std::string& resourceId = "");

		/*! Registers a group in the schema for this \c Settings instance

			\param group a unique identifier
			\param title a user friendly name appropriate for UI presentation
			\return True on success, False on failure
		*/
		bool RegisterGroup(const std::string& group, const std::string& title);

		/*! Registers a new setting with this \c Settings instance

			\param key a unique setting identifier in the form <b>'<group>.<name>'</b>
			\param properties a JSON string describes the setting schema
			\return True on success, False on failure.
		*/
		bool RegisterSetting(const std::string& key, const std::string& properties);

		/*! Determine if a setting identifier exists in the active settings schema

			\param key the setting identifier
			\return True if the identifier exists in this active settings schema, False otherwise
		*/
		bool Contains(const std::string& key);

		/*! Determine if the active settings schema is empty

			\return True if the active settings schema is empty, False otherwise
		*/
		bool IsEmpty();

		/*! Retrieve the list of setting identifiers in the active settings schema

			\return List of setting identifiers
		*/
		std::vector<std::string> Keys();

		template <typename T>
		T QueryProperty(const std::string& key, const std::string& property);

		bool UpdateProperty(const std::string& key, const std::string& property);
		bool UpdateProperty(const std::string& key, const std::string& property, bool value);
		bool UpdateProperty(const std::string& key, const std::string& property, double value);
		bool UpdateProperty(const std::string& key, const std::string& property, int value);
		bool UpdateProperty(const std::string& key, const std::string& property, int64_t value);
		bool UpdateProperty(const std::string& key, const std::string& property, uint64_t value);
		bool UpdateProperty(const std::string& key, const std::string& property, const char* value);
		bool UpdateProperty(const std::string& key, const std::string& property, const std::string& value);
		bool UpdateProperty(const std::string& key, const std::string& property, const std::vector<std::string>& value);

		bool DeserializeSchema(const std::string& schema, BNSettingsScope scope = SettingsAutoScope, bool merge = true);
		std::string SerializeSchema();
		bool DeserializeSettings(
		    const std::string& contents, Ref<BinaryView> view = nullptr, BNSettingsScope scope = SettingsAutoScope);
		std::string SerializeSettings(Ref<BinaryView> view = nullptr, BNSettingsScope scope = SettingsAutoScope);

		bool Reset(const std::string& key, Ref<BinaryView> view = nullptr, BNSettingsScope scope = SettingsAutoScope);
		bool ResetAll(
		    Ref<BinaryView> view = nullptr, BNSettingsScope scope = SettingsAutoScope, bool schemaOnly = true);

		/*! Get the current setting value for a particular key

			\code{.cpp}
		 	bool excludeUnreferencedStrings = Settings::Instance()->Get<bool>("ui.stringView.excludeUnreferencedStrings", data);
			\endcode

			\tparam T type for the value you are retrieving
			\param key Key for the setting
			\param view BinaryView, for factoring in resource-scoped settings
			\param scope Scope for the settings
			\return Value for the setting, with type T
		*/
		template <typename T>
		T Get(const std::string& key, Ref<BinaryView> view = nullptr, BNSettingsScope* scope = nullptr);

		/*! Get the current settings value for a particular key, as a JSON representation of its value.

			\code{.cpp}
		    string value = Settings::Instance()->GetJson("analysis.mode");
			// '"full"'
		 	\endcode

			\param key Key for the setting
			\param view BinaryView, for factoring in resource-scoped settings
			\param scope Scope for the settings
			\return JSON value for the setting, as a string
		*/
		std::string GetJson(const std::string& key, Ref<BinaryView> view = nullptr, BNSettingsScope* scope = nullptr);

		bool Set(const std::string& key, bool value, Ref<BinaryView> view = nullptr,
		    BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, double value, Ref<BinaryView> view = nullptr,
		    BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, int value, Ref<BinaryView> view = nullptr,
		    BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, int64_t value, Ref<BinaryView> view = nullptr,
		    BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, uint64_t value, Ref<BinaryView> view = nullptr,
		    BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, const char* value, Ref<BinaryView> view = nullptr,
		    BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, const std::string& value, Ref<BinaryView> view = nullptr,
		    BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, const std::vector<std::string>& value, Ref<BinaryView> view = nullptr,
		    BNSettingsScope scope = SettingsAutoScope);
		bool SetJson(const std::string& key, const std::string& value, Ref<BinaryView> view = nullptr,
		    BNSettingsScope scope = SettingsAutoScope);
	};

	// explicit specializations
	/*! \cond DOXYGEN_HIDE
		Prevent these from having docs autogenerated twice, due to an odd quirk with doxygen
	*/
	template <>
	std::vector<std::string> Settings::QueryProperty<std::vector<std::string>>(
	    const std::string& key, const std::string& property);
	template <>
	bool Settings::Get<bool>(const std::string& key, Ref<BinaryView> view, BNSettingsScope* scope);
	template <>
	double Settings::Get<double>(const std::string& key, Ref<BinaryView> view, BNSettingsScope* scope);
	template <>
	int64_t Settings::Get<int64_t>(const std::string& key, Ref<BinaryView> view, BNSettingsScope* scope);
	template <>
	uint64_t Settings::Get<uint64_t>(const std::string& key, Ref<BinaryView> view, BNSettingsScope* scope);
	template <>
	std::string Settings::Get<std::string>(const std::string& key, Ref<BinaryView> view, BNSettingsScope* scope);
	template <>
	std::vector<std::string> Settings::Get<std::vector<std::string>>(
	    const std::string& key, Ref<BinaryView> view, BNSettingsScope* scope);
	/*! \endcond */

	typedef BNMetadataType MetadataType;

	/*!
		\ingroup metadata
	*/
	class Metadata : public CoreRefCountObject<BNMetadata, BNNewMetadataReference, BNFreeMetadata>
	{
	  public:
		explicit Metadata(BNMetadata* structuredData);
		explicit Metadata(bool data);
		explicit Metadata(const std::string& data);
		explicit Metadata(uint64_t data);
		explicit Metadata(int64_t data);
		explicit Metadata(double data);
		explicit Metadata(const std::vector<bool>& data);
		explicit Metadata(const std::vector<std::string>& data);
		explicit Metadata(const std::vector<uint64_t>& data);
		explicit Metadata(const std::vector<int64_t>& data);
		explicit Metadata(const std::vector<double>& data);
		explicit Metadata(const std::vector<uint8_t>& data);
		explicit Metadata(const std::vector<Ref<Metadata>>& data);
		explicit Metadata(const std::map<std::string, Ref<Metadata>>& data);
		explicit Metadata(MetadataType type);
		virtual ~Metadata() {}

		bool operator==(const Metadata& rhs);
		Ref<Metadata> operator[](const std::string& key);
		Ref<Metadata> operator[](size_t idx);

		MetadataType GetType() const;
		bool GetBoolean() const;
		std::string GetString() const;
		uint64_t GetUnsignedInteger() const;
		int64_t GetSignedInteger() const;
		double GetDouble() const;
		std::vector<bool> GetBooleanList() const;
		std::vector<std::string> GetStringList() const;
		std::vector<uint64_t> GetUnsignedIntegerList() const;
		std::vector<int64_t> GetSignedIntegerList() const;
		std::vector<double> GetDoubleList() const;
		std::vector<uint8_t> GetRaw() const;
		std::vector<Ref<Metadata>> GetArray();
		std::map<std::string, Ref<Metadata>> GetKeyValueStore();

		// For key-value data only
		Ref<Metadata> Get(const std::string& key);
		bool SetValueForKey(const std::string& key, Ref<Metadata> data);
		void RemoveKey(const std::string& key);

		// For array data only
		Ref<Metadata> Get(size_t index);
		bool Append(Ref<Metadata> data);
		void RemoveIndex(size_t index);
		size_t Size() const;

		bool IsBoolean() const;
		bool IsString() const;
		bool IsUnsignedInteger() const;
		bool IsSignedInteger() const;
		bool IsDouble() const;
		bool IsBooleanList() const;
		bool IsStringList() const;
		bool IsUnsignedIntegerList() const;
		bool IsSignedIntegerList() const;
		bool IsDoubleList() const;
		bool IsRaw() const;
		bool IsArray() const;
		bool IsKeyValueStore() const;
	};

	/*! DataRenderer objects tell the Linear View how to render specific types.

		The `IsValidForData` method returns a boolean to indicate if your derived class
		is able to render the type, given the `addr` and `context`. The `context` is a list of Type
		objects which represents the chain of nested objects that is being displayed.

		The `GetLinesForData` method returns a list of `DisassemblyTextLine` objects, each one
		representing a single line of Linear View output. The `prefix` variable is a list of `InstructionTextToken`'s
		which have already been generated by other `DataRenderer`'s.

		After defining the `DataRenderer` subclass you must then register it with the core. This is done by calling
		either `DataRendererContainer::RegisterGenericDataRenderer()` or
	 	`DataRendererContainer::RegisterTypeSpecificDataRenderer()`.
	 	A "generic" type renderer is able to be overridden by a "type specific" renderer. For instance there is a
	 	generic struct render which renders any struct that hasn't been explicitly overridden by a "type specific" renderer.

		\ingroup datarenderer
	*/
	class DataRenderer : public CoreRefCountObject<BNDataRenderer, BNNewDataRendererReference, BNFreeDataRenderer>
	{
		static bool IsValidForDataCallback(
		    void* ctxt, BNBinaryView* data, uint64_t addr, BNType* type, BNTypeContext* typeCtx, size_t ctxCount);
		static BNDisassemblyTextLine* GetLinesForDataCallback(void* ctxt, BNBinaryView* data, uint64_t addr,
		    BNType* type, const BNInstructionTextToken* prefix, size_t prefixCount, size_t width, size_t* count,
		    BNTypeContext* typeCxt, size_t ctxCount);
		static void FreeCallback(void* ctxt);

	  public:
		DataRenderer();
		DataRenderer(BNDataRenderer* renderer);
		virtual bool IsValidForData(
		    BinaryView* data, uint64_t addr, Type* type, std::vector<std::pair<Type*, size_t>>& context);
		virtual std::vector<DisassemblyTextLine> GetLinesForData(BinaryView* data, uint64_t addr, Type* type,
		    const std::vector<InstructionTextToken>& prefix, size_t width,
		    std::vector<std::pair<Type*, size_t>>& context);
		std::vector<DisassemblyTextLine> RenderLinesForData(BinaryView* data, uint64_t addr, Type* type,
		    const std::vector<InstructionTextToken>& prefix, size_t width,
		    std::vector<std::pair<Type*, size_t>>& context);

		static bool IsStructOfTypeName(
		    Type* type, const QualifiedName& name, std::vector<std::pair<Type*, size_t>>& context);
		static bool IsStructOfTypeName(
		    Type* type, const std::string& name, std::vector<std::pair<Type*, size_t>>& context);
	};

	/*! Used for registering DataRenderers

		\see DataRenderer

		\ingroup datarenderer
	*/
	class DataRendererContainer
	{
	  public:
		static void RegisterGenericDataRenderer(DataRenderer* renderer);
		static void RegisterTypeSpecificDataRenderer(DataRenderer* renderer);
	};

	/*!

		\ingroup coreapi
	*/
	class DisassemblyTextRenderer :
	    public CoreRefCountObject<BNDisassemblyTextRenderer, BNNewDisassemblyTextRendererReference,
	        BNFreeDisassemblyTextRenderer>
	{
	  public:
		DisassemblyTextRenderer(Function* func, DisassemblySettings* settings = nullptr);
		DisassemblyTextRenderer(LowLevelILFunction* func, DisassemblySettings* settings = nullptr);
		DisassemblyTextRenderer(MediumLevelILFunction* func, DisassemblySettings* settings = nullptr);
		DisassemblyTextRenderer(HighLevelILFunction* func, DisassemblySettings* settings = nullptr);
		DisassemblyTextRenderer(BNDisassemblyTextRenderer* renderer);

		Ref<Function> GetFunction() const;
		Ref<LowLevelILFunction> GetLowLevelILFunction() const;
		Ref<MediumLevelILFunction> GetMediumLevelILFunction() const;
		Ref<HighLevelILFunction> GetHighLevelILFunction() const;

		Ref<BasicBlock> GetBasicBlock() const;
		Ref<Architecture> GetArchitecture() const;
		Ref<DisassemblySettings> GetSettings() const;
		void SetBasicBlock(BasicBlock* block);
		void SetArchitecture(Architecture* arch);
		void SetSettings(DisassemblySettings* settings);

		virtual bool IsIL() const;
		virtual bool HasDataFlow() const;

		virtual void GetInstructionAnnotations(std::vector<InstructionTextToken>& tokens, uint64_t addr);
		virtual bool GetInstructionText(uint64_t addr, size_t& len, std::vector<DisassemblyTextLine>& lines);
		std::vector<DisassemblyTextLine> PostProcessInstructionTextLines(uint64_t addr, size_t len,
		    const std::vector<DisassemblyTextLine>& lines, const std::string& indentSpaces = "");

		virtual bool GetDisassemblyText(uint64_t addr, size_t& len, std::vector<DisassemblyTextLine>& lines);
		void ResetDeduplicatedComments();

		bool AddSymbolToken(std::vector<InstructionTextToken>& tokens, uint64_t addr, size_t size, size_t operand);
		void AddStackVariableReferenceTokens(
		    std::vector<InstructionTextToken>& tokens, const StackVariableReference& ref);

		static bool IsIntegerToken(BNInstructionTextTokenType type);
		void AddIntegerToken(std::vector<InstructionTextToken>& tokens, const InstructionTextToken& token,
		    Architecture* arch, uint64_t addr);

		void WrapComment(DisassemblyTextLine& line, std::vector<DisassemblyTextLine>& lines, const std::string& comment,
		    bool hasAutoAnnotations, const std::string& leadingSpaces = "  ", const std::string& indentSpaces = "");
		static std::string GetDisplayStringForInteger(Ref<BinaryView> binaryView, BNIntegerDisplayType type,
		    uint64_t value, size_t inputWidth, bool isSigned = true);
	};

	/*!
		\ingroup lineardisassembly
	*/
	struct LinearViewObjectIdentifier
	{
		std::string name;
		BNLinearViewObjectIdentifierType type;
		uint64_t start, end;

		LinearViewObjectIdentifier();
		LinearViewObjectIdentifier(const std::string& name);
		LinearViewObjectIdentifier(const std::string& name, uint64_t addr);
		LinearViewObjectIdentifier(const std::string& name, uint64_t start, uint64_t end);
		LinearViewObjectIdentifier(const LinearViewObjectIdentifier& other);
	};

	/*!
		\ingroup lineardisassembly
	*/
	class LinearViewObject :
	    public CoreRefCountObject<BNLinearViewObject, BNNewLinearViewObjectReference, BNFreeLinearViewObject>
	{
	  public:
		LinearViewObject(BNLinearViewObject* obj);

		Ref<LinearViewObject> GetFirstChild();
		Ref<LinearViewObject> GetLastChild();
		Ref<LinearViewObject> GetPreviousChild(LinearViewObject* obj);
		Ref<LinearViewObject> GetNextChild(LinearViewObject* obj);

		Ref<LinearViewObject> GetChildForAddress(uint64_t addr);
		Ref<LinearViewObject> GetChildForIdentifier(const LinearViewObjectIdentifier& id);
		int CompareChildren(LinearViewObject* a, LinearViewObject* b);

		std::vector<LinearDisassemblyLine> GetLines(LinearViewObject* prev, LinearViewObject* next);

		uint64_t GetStart() const;
		uint64_t GetEnd() const;

		LinearViewObjectIdentifier GetIdentifier() const;

		uint64_t GetOrderingIndexTotal() const;
		uint64_t GetOrderingIndexForChild(LinearViewObject* obj) const;
		Ref<LinearViewObject> GetChildForOrderingIndex(uint64_t idx);

		static Ref<LinearViewObject> CreateDisassembly(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateLiftedIL(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateLowLevelIL(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateLowLevelILSSAForm(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateMediumLevelIL(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateMediumLevelILSSAForm(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateMappedMediumLevelIL(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateMappedMediumLevelILSSAForm(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateHighLevelIL(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateHighLevelILSSAForm(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateLanguageRepresentation(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateDataOnly(BinaryView* view, DisassemblySettings* settings);

		static Ref<LinearViewObject> CreateSingleFunctionDisassembly(Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionLiftedIL(Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionLowLevelIL(Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionLowLevelILSSAForm(
		    Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionMediumLevelIL(Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionMediumLevelILSSAForm(
		    Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionMappedMediumLevelIL(
		    Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionMappedMediumLevelILSSAForm(
		    Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionHighLevelIL(Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionHighLevelILSSAForm(
		    Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionLanguageRepresentation(
		    Function* func, DisassemblySettings* settings);
	};

	/*!
		\ingroup lineardisassembly
	*/
	class LinearViewCursor :
	    public CoreRefCountObject<BNLinearViewCursor, BNNewLinearViewCursorReference, BNFreeLinearViewCursor>
	{
	  public:
		LinearViewCursor(LinearViewObject* root);
		LinearViewCursor(BNLinearViewCursor* cursor);

		bool IsBeforeBegin() const;
		bool IsAfterEnd() const;
		bool IsValid() const;

		Ref<LinearViewObject> GetCurrentObject() const;
		std::vector<LinearViewObjectIdentifier> GetPath() const;
		std::vector<Ref<LinearViewObject>> GetPathObjects() const;
		BNAddressRange GetOrderingIndex() const;
		uint64_t GetOrderingIndexTotal() const;

		void SeekToBegin();
		void SeekToEnd();
		void SeekToAddress(uint64_t addr);
		bool SeekToPath(const std::vector<LinearViewObjectIdentifier>& path);
		bool SeekToPath(const std::vector<LinearViewObjectIdentifier>& path, uint64_t addr);
		bool SeekToPath(LinearViewCursor* cursor);
		bool SeekToPath(LinearViewCursor* cursor, uint64_t addr);
		void SeekToOrderingIndex(uint64_t idx);
		bool Next();
		bool Previous();

		std::vector<LinearDisassemblyLine> GetLines();

		Ref<LinearViewCursor> Duplicate();

		static int Compare(LinearViewCursor* a, LinearViewCursor* b);
	};

	/*!

		\ingroup simplifyname
	*/
	class SimplifyName
	{
	  public:
		// Use these functions to interface with the simplifier
		static std::string to_string(const std::string& input);
		static std::string to_string(const QualifiedName& input);
		static QualifiedName to_qualified_name(const std::string& input, bool simplify);
		static QualifiedName to_qualified_name(const QualifiedName& input);

		// Below is everything for the above APIs to work
		enum SimplifierDest
		{
			str,
			fqn
		};

		SimplifyName(const std::string&, const SimplifierDest, const bool);
		~SimplifyName();

		operator std::string() const;
		operator QualifiedName();

	  private:
		const char* m_rust_string;
		const char** m_rust_array;
		uint64_t m_length;
	};

	struct FindParameters
	{
		BNFindType type;
		BNFindRangeType rangeType;
		BNFunctionGraphType ilType;
		std::string string;
		BNFindFlag flags;
		bool findAll;

		uint64_t findConstant;
		DataBuffer findBuffer;

		std::vector<BNAddressRange> ranges;
		uint64_t totalLength;
	};

	/*!
		\ingroup debuginfo
	*/
	struct DebugFunctionInfo
	{
		std::string shortName;
		std::string fullName;
		std::string rawName;
		uint64_t address;
		Ref<Type> type;
		Ref<Platform> platform;

		DebugFunctionInfo(std::string shortName, std::string fullName, std::string rawName, uint64_t address,
		    Ref<Type> type, Ref<Platform> platform) :
		    shortName(shortName),
		    fullName(fullName), rawName(rawName), address(address), platform(platform)
		{}
	};

	/*!
		\ingroup debuginfo
	*/
	class DebugInfo : public CoreRefCountObject<BNDebugInfo, BNNewDebugInfoReference, BNFreeDebugInfoReference>
	{
	  public:
		DebugInfo(BNDebugInfo* debugInfo);

		std::vector<std::string> GetParsers() const;

		std::vector<NameAndType> GetTypes(const std::string& parserName = "") const;
		std::vector<DebugFunctionInfo> GetFunctions(const std::string& parserName = "") const;
		std::vector<DataVariableAndName> GetDataVariables(const std::string& parserName = "") const;

		Ref<Type> GetTypeByName(const std::string& parserName, const std::string& name) const;
		std::optional<std::tuple<uint64_t, Ref<Type>>> GetDataVariableByName(
			const std::string& parserName, const std::string& name) const;
		std::optional<std::tuple<std::string, Ref<Type>>> GetDataVariableByAddress(
			const std::string& parserName, const uint64_t address) const;

		std::vector<std::tuple<std::string, Ref<Type>>> GetTypesByName(const std::string& name) const;
		std::vector<std::tuple<std::string, uint64_t, Ref<Type>>> GetDataVariablesByName(const std::string& name) const;
		std::vector<std::tuple<std::string, std::string, Ref<Type>>> GetDataVariablesByAddress(
			const uint64_t address) const;

		bool RemoveParserInfo(const std::string& parserName);
		bool RemoveParserTypes(const std::string& parserName);
		bool RemoveParserFunctions(const std::string& parserName);
		bool RemoveParserDataVariables(const std::string& parserName);

		bool RemoveTypeByName(const std::string& parserName, const std::string& name);
		bool RemoveFunctionByIndex(const std::string& parserName, const size_t index);
		bool RemoveDataVariableByAddress(const std::string& parserName, const uint64_t address);

		bool AddType(const std::string& name, Ref<Type> type);
		bool AddFunction(const DebugFunctionInfo& function);
		bool AddDataVariable(uint64_t address, Ref<Type> type, const std::string& name = "");
	};

	/*!
		\ingroup debuginfo
	*/
	class DebugInfoParser :
	    public CoreRefCountObject<BNDebugInfoParser, BNNewDebugInfoParserReference, BNFreeDebugInfoParserReference>
	{
	  public:
		DebugInfoParser(BNDebugInfoParser* parser);

		static Ref<DebugInfoParser> GetByName(const std::string& name);
		static std::vector<Ref<DebugInfoParser>> GetList();
		static std::vector<Ref<DebugInfoParser>> GetListForView(const Ref<BinaryView> data);

		std::string GetName() const;
		Ref<DebugInfo> Parse(Ref<BinaryView> view, Ref<DebugInfo> existingDebugInfo = nullptr, std::function<bool(size_t, size_t)> progress = {}) const;

		bool IsValidForView(const Ref<BinaryView> view) const;
	};

	/*!
		\ingroup debuginfo
	*/
	class CustomDebugInfoParser : public DebugInfoParser
	{
		static bool IsValidCallback(void* ctxt, BNBinaryView* view);
		static bool ParseCallback(void* ctxt, BNDebugInfo* debugInfo, BNBinaryView* view, bool (*progress)(void*, size_t, size_t), void* progressCtxt);
		BNDebugInfoParser* Register(const std::string& name);

	  public:
		CustomDebugInfoParser(const std::string& name);
		virtual ~CustomDebugInfoParser() {}

		virtual bool IsValid(Ref<BinaryView>) = 0;
		virtual bool ParseInfo(Ref<DebugInfo>, Ref<BinaryView>, std::function<bool(size_t, size_t)>) = 0;
	};

	/*! Class for storing secrets (e.g. tokens) in a system-specific manner

	 	\ingroup secretsprovider
	*/
	class SecretsProvider : public StaticCoreRefCountObject<BNSecretsProvider>
	{
		std::string m_nameForRegister;

	  protected:
		SecretsProvider(const std::string& name);
		SecretsProvider(BNSecretsProvider* provider);

		static bool HasDataCallback(void* ctxt, const char* key);
		static char* GetDataCallback(void* ctxt, const char* key);
		static bool StoreDataCallback(void* ctxt, const char* key, const char* data);
		static bool DeleteDataCallback(void* ctxt, const char* key);

	  public:
		/*! Check if data for a specific key exists, but do not retrieve it

		    \param key Key for data
		    \return True if data exists
		*/
		virtual bool HasData(const std::string& key) = 0;

		/*! Retrieve data for the given key, if it exists

		    \param key Key for data
		    \return Optional with data, if it exists, or empty optional if it does not exist
		            or otherwise could not be retrieved.
		*/
		virtual std::optional<std::string> GetData(const std::string& key) = 0;

		/*! Store data with the given key

		    \param key Key for data
		    \param data Data to store
		    \return True if the data was stored
		*/
		virtual bool StoreData(const std::string& key, const std::string& data) = 0;

		/*! Delete stored data with the given key

		    \param key Key for data
		    \return True if it was deleted
		*/
		virtual bool DeleteData(const std::string& key) = 0;

		/*! Retrieve the list of providers

		    \return A list of registered providers
		*/
		static std::vector<Ref<SecretsProvider>> GetList();
		/*! Retrieve a provider by name

		    \param name Name of provider
		    \return Provider object, if one with the given name is regestered, or nullptr if not
		*/
		static Ref<SecretsProvider> GetByName(const std::string& name);
		/*! Register a new provider

		    \param provider New provider to register
		*/
		static void Register(SecretsProvider* provider);
	};

	/*!

		\ingroup secretsprovider
	*/
	class CoreSecretsProvider : public SecretsProvider
	{
	  public:
		CoreSecretsProvider(BNSecretsProvider* provider);

		virtual bool HasData(const std::string& key) override;
		virtual std::optional<std::string> GetData(const std::string& key) override;
		virtual bool StoreData(const std::string& key, const std::string& data) override;
		virtual bool DeleteData(const std::string& key) override;
	};

	/*! Components are objects that can contain Functions and other Components.

		\note Components should not be instantiated directly. Instead use BinaryView::CreateComponent()

		They can be queried for information about the functions contained within them.

	 	Components have a Guid, which persistent across saves and loads of the database, and should be
	 	used for retrieving components when such is required and a reference to the Component cannot be held.

	 	\ingroup coreapi

	*/
	class Component : public CoreRefCountObject<BNComponent, BNNewComponentReference, BNFreeComponent>
	{
	public:
		Component(BNComponent* type);

		/*! Get the unique identifier for this component.

			\return Component GUID
		*/
		std::string GetGuid();

		bool operator==(const Component& other) const;
		bool operator!=(const Component& other) const;

		Ref<BinaryView> GetView();

		/*! The displayed name for the component

			This can differ from the GetOriginalName() value if the parent
		 	component also contains other components with the same name.

		 	Subsequent duplicates will return the original name with " (1)", " (2)" and so on appended.

		 	This name can change whenever a different duplicate is removed.

		 	\note For looking up Components, utilizing Guid is highly recommended, as it will *always* map to this component,
		 	and as Guid lookups are faster by nature.

			\return Component name
		*/
		std::string GetDisplayName();

		/*! The original name for the component

			This may differ from Component::GetName() whenever the parent contains Components with the same original name.

		 	This function will always return the value originally set for this Component.

			\return Component name
		*/
		std::string GetName();

		/*! Set the name for the component

			\see GetName(), GetOriginalName()

		    \param name New component name.
		*/
		void SetName(const std::string &name);

		/*! Get the parent component. If it's a top level component, it will return the "root" Component.

			\return Parent Component
		*/
		Ref<Component> GetParent();

		/*! Add a function to this component

			\param func Function to add.
			\return True if the function was successfully added.
		*/
		bool AddFunction(Ref<Function> func);

		/*! Move a component to this component.

			\param component Component to add.
			\return True if the component was successfully added.
		*/
		bool AddComponent(Ref<Component> component);

		/*! Remove a Component from this Component, moving it to the root component.

			This will not remove a component from the tree entirely.

			\see BinaryView::GetRootComponent(), BinaryView::RemoveComponent()

			\param component Component to remove
			\return True if the component was successfully removed
		*/
		bool RemoveComponent(Ref<Component> component);

		/*! Remove a function

			\param func Function to remove
			\return True if the function was successfully removed.
		*/
		bool RemoveFunction(Ref<Function> func);

		/*! Get a list of types referenced by the functions in this Component.

			\return vector of Type objects
		*/
		std::vector<Ref<Type>> GetReferencedTypes();

		/*! Get a list of components contained by this component.

			\return vector of Component objects
		*/
		std::vector<Ref<Component>> GetContainedComponents();

		/*! Get a list of functions contained within this Component.

			\return vector of Function objects
		*/
		std::vector<Ref<Function>> GetContainedFunctions();

		/*! Get a list of DataVariables referenced by the functions in this Component.

			\return vector of DataVariable objects
		*/
		std::vector<DataVariable> GetReferencedDataVariables();
	};

}  // namespace BinaryNinja
