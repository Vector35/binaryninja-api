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


namespace BinaryNinja {
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

	class FileMetadata;
	class BinaryView;
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

	std::string EscapeString(const std::string& s);
	std::string UnescapeString(const std::string& s);

	bool PreprocessSource(const std::string& source, const std::string& fileName, std::string& output,
	    std::string& errors, const std::vector<std::string>& includeDirs = std::vector<std::string>());

	void DisablePlugins();
	bool IsPluginsEnabled();
	bool InitPlugins(bool allowUserPlugins = true);
	void InitCorePlugins();  // Deprecated, use InitPlugins
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

	class BinaryView;

	/*!
	    OpenView opens a file on disk and returns a BinaryView, attempting to use the most
	    relevant BinaryViewType and generating default load options (which are overridable).

	    If there is any error loading the file, nullptr will be returned and a log error will
	    be printed.

	    Warning: You will need to call bv->GetFile()->Close() when you are finished using the
	    view returned by this function to free the resources it opened.

	    If no BinaryViewType is available to load the file, the `Mapped` view type will
	    attempt to load it, and will try to auto-detect the architecture. If no architecture
	    is detected or specified in the load options, the `Mapped` type will fail and this
	    function will also return nullptr.

	    Note: Although general container file support is not complete, support for Universal
	    archives exists. It's possible to control the architecture preference with the
	    `files.universal.architecturePreference` setting. This setting is scoped to
	    SettingsUserScope and can be modified as follows:

	        Json::Value options(Json::objectValue);
	        options["files.universal.architecturePreference"] = Json::Value(Json::arrayValue);
	        options["files.universal.architecturePreference"].append("arm64");
	        Ref<BinaryView> bv = OpenView("/bin/ls", true, {}, options);

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

	/*!
	    Open a BinaryView from a raw data buffer, initializing data views and loading settings.

	    See BinaryNinja::OpenView(const std::string&, bool, std::function<bool(size_t, size_t)>, Json::Value)
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


	/*!
	    Open a BinaryView from a raw BinaryView, initializing data views and loading settings.

	    See BinaryNinja::OpenView(const std::string&, bool, std::function<bool(size_t, size_t)>, Json::Value)
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

	/*!
	    DemangleMS demangles a Microsoft Visual Studio C++ name

	    \param arch Architecture for the symbol. Required for pointer and integer sizes.
	    \param mangledName a mangled Microsoft Visual Studio C++ name
	    \param outType Pointer to Type to output
	    \param outVarName QualifiedName reference to write the output name to.
	    \param simplify Whether to simplify demangled names.
	 */
	bool DemangleMS(Architecture* arch, const std::string& mangledName, Type** outType, QualifiedName& outVarName,
	    const bool simplify = false);

	/*!
	    DemangleMS demangles a Microsoft Visual Studio C++ name

	    This overload will use the view's "analysis.types.templateSimplifier" setting
	    	to determine whether to simplify the mangled name.

		\param arch Architecture for the symbol. Required for pointer and integer sizes.
	    \param mangledName a mangled Microsoft Visual Studio C++ name
	    \param outType Pointer to Type to output
	    \param outVarName QualifiedName reference to write the output name to.
	    \param view View to check the analysis.types.templateSimplifier for
	 */
	bool DemangleMS(Architecture* arch, const std::string& mangledName, Type** outType, QualifiedName& outVarName,
	    const Ref<BinaryView>& view);

	/*!
	    DemangleGNU3 demangles a GNU3 name

		\param arch Architecture for the symbol. Required for pointer and integer sizes.
	    \param mangledName a mangled GNU3 name
	    \param outType Pointer to Type to output
	    \param outVarName QualifiedName reference to write the output name to.
	    \param simplify Whether to simplify demangled names.
	 */
	bool DemangleGNU3(Ref<Architecture> arch, const std::string& mangledName, Type** outType, QualifiedName& outVarName,
	    const bool simplify = false);

	/*!
	    DemangleGNU3 demangles a GNU3 name

	    This overload will use the view's "analysis.types.templateSimplifier" setting
	        to determine whether to simplify the mangled name.

		\param arch Architecture for the symbol. Required for pointer and integer sizes.
	    \param mangledName a mangled GNU3 name
	    \param outType Pointer to Type to output
	    \param outVarName QualifiedName reference to write the output name to.
	    \param view View to check the analysis.types.templateSimplifier for
	 */
	bool DemangleGNU3(Ref<Architecture> arch, const std::string& mangledName, Type** outType, QualifiedName& outVarName,
	    const Ref<BinaryView>& view);

	void RegisterMainThread(MainThreadActionHandler* handler);
	Ref<MainThreadAction> ExecuteOnMainThread(const std::function<void()>& action);
	void ExecuteOnMainThreadAndWait(const std::function<void()>& action);
	bool IsMainThread();

	void WorkerEnqueue(const std::function<void()>& action);
	void WorkerEnqueue(RefCountObject* owner, const std::function<void()>& action);
	void WorkerPriorityEnqueue(const std::function<void()>& action);
	void WorkerPriorityEnqueue(RefCountObject* owner, const std::function<void()>& action);
	void WorkerInteractiveEnqueue(const std::function<void()>& action);
	void WorkerInteractiveEnqueue(RefCountObject* owner, const std::function<void()>& action);

	size_t GetWorkerThreadCount();
	void SetWorkerThreadCount(size_t count);

	std::string MarkdownToHTML(const std::string& contents);

	void RegisterInteractionHandler(InteractionHandler* handler);

	void ShowPlainTextReport(const std::string& title, const std::string& contents);
	void ShowMarkdownReport(const std::string& title, const std::string& contents, const std::string& plainText = "");
	void ShowHTMLReport(const std::string& title, const std::string& contents, const std::string& plainText = "");
	void ShowGraphReport(const std::string& title, FlowGraph* graph);
	void ShowReportCollection(const std::string& title, ReportCollection* reports);

	bool GetTextLineInput(std::string& result, const std::string& prompt, const std::string& title);
	bool GetIntegerInput(int64_t& result, const std::string& prompt, const std::string& title);
	bool GetAddressInput(uint64_t& result, const std::string& prompt, const std::string& title);
	bool GetChoiceInput(
	    size_t& idx, const std::string& prompt, const std::string& title, const std::vector<std::string>& choices);
	bool GetOpenFileNameInput(std::string& result, const std::string& prompt, const std::string& ext = "");
	bool GetSaveFileNameInput(std::string& result, const std::string& prompt, const std::string& ext = "",
	    const std::string& defaultName = "");
	bool GetDirectoryNameInput(std::string& result, const std::string& prompt, const std::string& defaultName = "");
	bool GetFormInput(std::vector<FormInputField>& fields, const std::string& title);

	BNMessageBoxButtonResult ShowMessageBox(const std::string& title, const std::string& text,
	    BNMessageBoxButtonSet buttons = OKButtonSet, BNMessageBoxIcon icon = InformationIcon);

	bool OpenUrl(const std::string& url);

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

	std::string GetUniqueIdentifierString();

	std::map<std::string, uint64_t> GetMemoryUsageInfo();

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

	/*!
		TemporaryFile is used for creating temporary files, stored (temporarily) in the system's default temporary file
	 		directory.
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

	struct InstructionTextToken;
	struct UndoEntry;

	struct DatabaseException : std::runtime_error
	{
		DatabaseException(const std::string& desc) : std::runtime_error(desc.c_str()) {}
	};

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

	class Snapshot : public CoreRefCountObject<BNSnapshot, BNNewSnapshotReference, BNFreeSnapshot>
	{
	  public:
		Snapshot(BNSnapshot* snapshot);

		Ref<Database> GetDatabase();
		int64_t GetId();
		std::string GetName();
		bool IsAutoSave();
		bool HasContents();
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

	class Database : public CoreRefCountObject<BNDatabase, BNNewDatabaseReference, BNFreeDatabase>
	{
	  public:
		Database(BNDatabase* database);

		Ref<Snapshot> GetSnapshot(int64_t id);
		std::vector<Ref<Snapshot>> GetSnapshots();
		void SetCurrentSnapshot(int64_t id);
		Ref<Snapshot> GetCurrentSnapshot();
		int64_t WriteSnapshotData(std::vector<int64_t> parents, Ref<BinaryView> file, const std::string& name,
		    const Ref<KeyValueStore>& data, bool autoSave, const std::function<bool(size_t, size_t)>& progress);
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

	struct UndoAction
	{
		BNActionType actionType;
		std::string summaryText;
		std::vector<InstructionTextToken> summaryTokens;

		UndoAction() {};
		UndoAction(const BNUndoAction& action);
	};

	struct UndoEntry
	{
		Ref<User> user;
		std::string hash;
		std::vector<UndoAction> actions;
		uint64_t timestamp;
	};

	struct MergeResult
	{
		BNMergeStatus status;
		UndoAction action;
		std::string hash;

		MergeResult() : status(NOT_APPLICABLE) {}
		MergeResult(const BNMergeResult& result);
	};

	class SaveSettings : public CoreRefCountObject<BNSaveSettings, BNNewSaveSettingsReference, BNFreeSaveSettings>
	{
	  public:
		SaveSettings();
		SaveSettings(BNSaveSettings* settings);

		bool IsOptionSet(BNSaveOption option) const;
		void SetOption(BNSaveOption option, bool state = true);
	};

	class FileMetadata : public CoreRefCountObject<BNFileMetadata, BNNewFileReference, BNFreeFileMetadata>
	{
	  public:
		FileMetadata();
		FileMetadata(const std::string& filename);
		FileMetadata(BNFileMetadata* file);

		/*!
		    Close the underlying file handle
		*/
		void Close();

		void SetNavigationHandler(NavigationHandler* handler);

		/*!
			\return The original name of the binary opened if a bndb, otherwise returns the current filename
		*/
		std::string GetOriginalFilename() const;

		/*!
			If the filename is not open in a BNDB, sets the filename for the current file.

			\param name New name
		*/
		void SetOriginalFilename(const std::string& name);

		/*!
			\return The name of the open bndb or binary filename
		*/
		std::string GetFilename() const;

		/*!
		 	\param name Set the filename for the currnt BNDB or binary.
		*/
		void SetFilename(const std::string& name);

		/*!
			\return Whether the file has unsaved modifications
		*/
		bool IsModified() const;

		/*!
			\return Whether auto-analysis results have changed.
		*/
		bool IsAnalysisChanged() const;

		/*!
			Mark file as having unsaved changes
		*/
		void MarkFileModified();

		/*!
			Mark file as having been saved (inverse of MarkFileModified)
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
		void ClearUndoEntries();

		bool OpenProject();
		void CloseProject();
		bool IsProjectOpen();

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

		/*!
		    Get the BinaryView for a specific View type

		    \param name View name. e.g. ``Linear:ELF``, ``Graph:PE``
		    \return The BinaryView, if it exists
		*/
		BinaryNinja::Ref<BinaryNinja::BinaryView> GetViewOfType(const std::string& name);

		/*!
		    List of View names that exist within the current file

		    \return List of View Names
		*/
		std::vector<std::string> GetExistingViews() const;

		/*!
		    \return Current Session ID
		*/
		size_t GetSessionId() const;
	};

	class Function;
	struct DataVariable;
	class Symbol;
	class Tag;
	class TagType;
	struct TagReference;
	class Section;
	class Segment;

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
	};

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

	struct AnalysisInfo
	{
		BNAnalysisState state;
		uint64_t analysisTime;
		std::vector<ActiveAnalysisInfo> activeInfo;
	};

	struct DataVariable
	{
		DataVariable() {}
		DataVariable(uint64_t a, Type* t, bool d) : address(a), type(t), autoDiscovered(d) {}

		uint64_t address;
		Confidence<Ref<Type>> type;
		bool autoDiscovered;
	};

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

		void SetStart(uint64_t newSegmentBase);
		void SetLength(uint64_t length);
		void SetDataOffset(uint64_t dataOffset);
		void SetDataLength(uint64_t dataLength);
		void SetFlags(uint32_t flags);
	};

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

	class QueryMetadataException : public std::exception
	{
		const std::string m_error;

	  public:
		QueryMetadataException(const std::string& error) : std::exception(), m_error(error) {}
		virtual const char* what() const NOEXCEPT { return m_error.c_str(); }
	};

	/*! BinaryView is the base class for creating views on binary data (e.g. ELF, PE, Mach-O).
	    BinaryView should be subclassed to create a new BinaryView
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

		    \param offset a virtual address to be checked
		    \return one of Original, Changed, Inserted
		*/
		virtual BNModificationStatus PerformGetModification(uint64_t offset)
		{
			(void)offset;
			return Original;
		}

		/*! PerformIsValidOffset implements a check as to whether a virtual address `offset` is valid

		    \param offset the virtual address to check
		    \return whether the offset is valid
		*/
		virtual bool PerformIsValidOffset(uint64_t offset);

		/*! PerformIsOffsetReadable implements a check as to whether a virtual address is readable

		    \param offset the virtual address to check
		    \return whether the offset is readable
		*/
		virtual bool PerformIsOffsetReadable(uint64_t offset);

		/*! PerformIsOffsetWritable implements a check as to whether a virtual address is writable

		    \param offset the virtual address to check
		    \return whether the offset is writable
		*/
		virtual bool PerformIsOffsetWritable(uint64_t offset);

		/*! PerformIsOffsetExecutable implements a check as to whether a virtual address is executable

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

		    \param offset a virtual address to start checking from
		    \return the next valid address
		*/
		virtual uint64_t PerformGetNextValidOffset(uint64_t offset);

		/*! PerformGetStart implements a query for the first readable, writable, or executable virtual address in the BinaryView

		    \return the first virtual address in the BinaryView
		*/
		virtual uint64_t PerformGetStart() const { return 0; }
		virtual uint64_t PerformGetLength() const { return 0; }
		virtual uint64_t PerformGetEntryPoint() const { return 0; }

		/*! PerformIsExecutable implements a check which returns true if the BinaryView is executable.

		    \return whether the BinaryView is executable
		*/
		virtual bool PerformIsExecutable() const { return false; }

		/*! PerformGetDefaultEndianness implements a check which returns the Endianness of the BinaryView

		    \return either LittleEndian or BigEndian
		*/
		virtual BNEndianness PerformGetDefaultEndianness() const;

		/*! PerformIsRelocatable implements a check which returns true if the BinaryView is relocatable.

		    \return whether the BinaryView is relocatable
		*/
		virtual bool PerformIsRelocatable() const;

		/*! PerformGetAddressSize implements a query for the address size for this BinaryView

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
		 *
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

		// References to type field
		std::vector<TypeFieldReference> GetCodeReferencesForTypeField(const QualifiedName& type, uint64_t offset);
		std::vector<uint64_t> GetDataReferencesForTypeField(const QualifiedName& type, uint64_t offset);
		std::vector<TypeReferenceSource> GetTypeReferencesForTypeField(const QualifiedName& type, uint64_t offset);

		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFrom(ReferenceSource src);
		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFrom(ReferenceSource src, uint64_t len);
		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFieldFrom(ReferenceSource src);
		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFieldFrom(ReferenceSource src, uint64_t len);

		std::vector<uint64_t> GetAllFieldsReferenced(const QualifiedName& type);
		std::map<uint64_t, std::vector<size_t>> GetAllSizesReferenced(const QualifiedName& type);
		std::map<uint64_t, std::vector<Confidence<Ref<Type>>>> GetAllTypesReferenced(const QualifiedName& type);
		std::vector<size_t> GetSizesReferenced(const QualifiedName& type, uint64_t offset);
		std::vector<Confidence<Ref<Type>>> GetTypesReferenced(const QualifiedName& type, uint64_t offset);

		Ref<Structure> CreateStructureBasedOnFieldAccesses(const QualifiedName& type);

		std::vector<uint64_t> GetCallees(ReferenceSource addr);
		std::vector<ReferenceSource> GetCallers(uint64_t addr);

		Ref<Symbol> GetSymbolByAddress(uint64_t addr, const NameSpace& nameSpace = NameSpace());
		Ref<Symbol> GetSymbolByRawName(const std::string& name, const NameSpace& nameSpace = NameSpace());
		std::vector<Ref<Symbol>> GetSymbolsByName(const std::string& name, const NameSpace& nameSpace = NameSpace());
		std::vector<Ref<Symbol>> GetSymbols(const NameSpace& nameSpace = NameSpace());
		std::vector<Ref<Symbol>> GetSymbols(uint64_t start, uint64_t len, const NameSpace& nameSpace = NameSpace());
		std::vector<Ref<Symbol>> GetSymbolsOfType(BNSymbolType type, const NameSpace& nameSpace = NameSpace());
		std::vector<Ref<Symbol>> GetSymbolsOfType(
		    BNSymbolType type, uint64_t start, uint64_t len, const NameSpace& nameSpace = NameSpace());
		std::vector<Ref<Symbol>> GetVisibleSymbols(const NameSpace& nameSpace = NameSpace());

		void DefineAutoSymbol(Ref<Symbol> sym);
		Ref<Symbol> DefineAutoSymbolAndVariableOrFunction(Ref<Platform> platform, Ref<Symbol> sym, Ref<Type> type);
		void UndefineAutoSymbol(Ref<Symbol> sym);

		void DefineUserSymbol(Ref<Symbol> sym);
		void UndefineUserSymbol(Ref<Symbol> sym);

		void DefineImportedFunction(Ref<Symbol> importAddressSym, Ref<Function> func, Ref<Type> type = nullptr);

		void BeginBulkModifySymbols();
		void EndBulkModifySymbols();

		void AddTagType(Ref<TagType> tagType);
		void RemoveTagType(Ref<TagType> tagType);
		Ref<TagType> GetTagType(const std::string& name);
		Ref<TagType> GetTagType(const std::string& name, TagType::Type type);
		Ref<TagType> GetTagTypeByName(const std::string& name);
		Ref<TagType> GetTagTypeByName(const std::string& name, TagType::Type type);
		Ref<TagType> GetTagTypeById(const std::string& id);
		Ref<TagType> GetTagTypeById(const std::string& id, TagType::Type type);
		std::vector<Ref<TagType>> GetTagTypes();

		void AddTag(Ref<Tag> tag, bool user = false);
		void RemoveTag(Ref<Tag> tag, bool user = false);
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

		bool CanAssemble(Architecture* arch);

		bool IsNeverBranchPatchAvailable(Architecture* arch, uint64_t addr);
		bool IsAlwaysBranchPatchAvailable(Architecture* arch, uint64_t addr);
		bool IsInvertBranchPatchAvailable(Architecture* arch, uint64_t addr);
		bool IsSkipAndReturnZeroPatchAvailable(Architecture* arch, uint64_t addr);
		bool IsSkipAndReturnValuePatchAvailable(Architecture* arch, uint64_t addr);
		bool ConvertToNop(Architecture* arch, uint64_t addr);
		bool AlwaysBranch(Architecture* arch, uint64_t addr);
		bool InvertBranch(Architecture* arch, uint64_t addr);
		bool SkipAndReturnValue(Architecture* arch, uint64_t addr, uint64_t value);
		size_t GetInstructionLength(Architecture* arch, uint64_t addr);

		bool GetStringAtAddress(uint64_t addr, BNStringReference& strRef);
		std::vector<BNStringReference> GetStrings();
		std::vector<BNStringReference> GetStrings(uint64_t start, uint64_t len);

		Ref<AnalysisCompletionEvent> AddAnalysisCompletionEvent(const std::function<void()>& callback);

		AnalysisInfo GetAnalysisInfo();
		BNAnalysisProgress GetAnalysisProgress();
		Ref<BackgroundTask> GetBackgroundAnalysisTask();

		uint64_t GetNextFunctionStartAfterAddress(uint64_t addr);
		uint64_t GetNextBasicBlockStartAfterAddress(uint64_t addr);
		uint64_t GetNextDataAfterAddress(uint64_t addr);
		uint64_t GetNextDataVariableStartAfterAddress(uint64_t addr);
		uint64_t GetPreviousFunctionStartBeforeAddress(uint64_t addr);
		uint64_t GetPreviousBasicBlockStartBeforeAddress(uint64_t addr);
		uint64_t GetPreviousBasicBlockEndBeforeAddress(uint64_t addr);
		uint64_t GetPreviousDataBeforeAddress(uint64_t addr);
		uint64_t GetPreviousDataVariableStartBeforeAddress(uint64_t addr);

		bool ParsePossibleValueSet(const std::string& value, BNRegisterValueType state, PossibleValueSet& result,
		    uint64_t here, std::string& errors);

		bool ParseTypeString(const std::string& text, QualifiedNameAndType& result, std::string& errors,
		    const std::set<QualifiedName>& typesAllowRedefinition = {});
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

		void ShowPlainTextReport(const std::string& title, const std::string& contents);
		void ShowMarkdownReport(const std::string& title, const std::string& contents, const std::string& plainText);
		void ShowHTMLReport(const std::string& title, const std::string& contents, const std::string& plainText);
		void ShowGraphReport(const std::string& title, FlowGraph* graph);
		bool GetAddressInput(uint64_t& result, const std::string& prompt, const std::string& title);
		bool GetAddressInput(
		    uint64_t& result, const std::string& prompt, const std::string& title, uint64_t currentAddress);

		void AddAutoSegment(uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags);
		void RemoveAutoSegment(uint64_t start, uint64_t length);
		void AddUserSegment(uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags);
		void RemoveUserSegment(uint64_t start, uint64_t length);
		std::vector<Ref<Segment>> GetSegments();
		Ref<Segment> GetSegmentAt(uint64_t addr);
		bool GetAddressForDataOffset(uint64_t offset, uint64_t& addr);

		void AddAutoSection(const std::string& name, uint64_t start, uint64_t length,
		    BNSectionSemantics semantics = DefaultSectionSemantics, const std::string& type = "", uint64_t align = 1,
		    uint64_t entrySize = 0, const std::string& linkedSection = "", const std::string& infoSection = "",
		    uint64_t infoData = 0);
		void RemoveAutoSection(const std::string& name);
		void AddUserSection(const std::string& name, uint64_t start, uint64_t length,
		    BNSectionSemantics semantics = DefaultSectionSemantics, const std::string& type = "", uint64_t align = 1,
		    uint64_t entrySize = 0, const std::string& linkedSection = "", const std::string& infoSection = "",
		    uint64_t infoData = 0);
		void RemoveUserSection(const std::string& name);
		std::vector<Ref<Section>> GetSections();
		std::vector<Ref<Section>> GetSectionsAt(uint64_t addr);
		Ref<Section> GetSectionByName(const std::string& name);

		std::vector<std::string> GetUniqueSectionNames(const std::vector<std::string>& names);

		std::string GetCommentForAddress(uint64_t addr) const;
		std::vector<uint64_t> GetCommentedAddresses() const;
		void SetCommentForAddress(uint64_t addr, const std::string& comment);

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

		std::set<NameSpace> GetNameSpaces() const;
		static NameSpace GetInternalNameSpace();
		static NameSpace GetExternalNameSpace();

		static bool ParseExpression(Ref<BinaryView> view, const std::string& expression, uint64_t& offset,
		    uint64_t here, std::string& errorString);
		bool HasSymbols() const;
		bool HasDataVariables() const;

		Ref<Structure> CreateStructureFromOffsetAccess(const QualifiedName& type, bool* newMemberAdded) const;
		Confidence<Ref<Type>> CreateStructureMemberFromAccess(const QualifiedName& name, uint64_t offset) const;

		Ref<Logger> CreateLogger(const std::string& name);
	};


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

		static void Register(BinaryViewType* type);
		static Ref<BinaryViewType> GetByName(const std::string& name);
		static std::vector<Ref<BinaryViewType>> GetViewTypes();
		static std::vector<Ref<BinaryViewType>> GetViewTypesForData(BinaryView* data);

		static void RegisterArchitecture(const std::string& name, uint32_t id, BNEndianness endian, Architecture* arch);
		void RegisterArchitecture(uint32_t id, BNEndianness endian, Architecture* arch);
		Ref<Architecture> GetArchitecture(uint32_t id, BNEndianness endian);

		static void RegisterPlatform(const std::string& name, uint32_t id, Architecture* arch, Platform* platform);
		static void RegisterDefaultPlatform(const std::string& name, Architecture* arch, Platform* platform);
		void RegisterPlatform(uint32_t id, Architecture* arch, Platform* platform);
		void RegisterDefaultPlatform(Architecture* arch, Platform* platform);
		Ref<Platform> GetPlatform(uint32_t id, Architecture* arch);

		void RegisterPlatformRecognizer(uint64_t id, BNEndianness endian,
		    const std::function<Ref<Platform>(BinaryView* view, Metadata*)>& callback);
		Ref<Platform> RecognizePlatform(uint64_t id, BNEndianness endian, BinaryView* view, Metadata* metadata);

		std::string GetName();
		std::string GetLongName();

		virtual bool IsDeprecated();

		virtual BinaryView* Create(BinaryView* data) = 0;
		virtual BinaryView* Parse(BinaryView* data) = 0;
		virtual bool IsTypeValidForData(BinaryView* data) = 0;
		virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) = 0;

		static void RegisterBinaryViewFinalizationEvent(const std::function<void(BinaryView* view)>& callback);
		static void RegisterBinaryViewInitialAnalysisCompletionEvent(
		    const std::function<void(BinaryView* view)>& callback);

		static void BinaryViewEventCallback(void* ctxt, BNBinaryView* view);
		static BNPlatform* PlatformRecognizerCallback(void* ctxt, BNBinaryView* view, BNMetadata* metadata);
	};

	class CoreBinaryViewType : public BinaryViewType
	{
	  public:
		CoreBinaryViewType(BNBinaryViewType* type);
		virtual BinaryView* Create(BinaryView* data) override;
		virtual BinaryView* Parse(BinaryView* data) override;
		virtual bool IsTypeValidForData(BinaryView* data) override;
		virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override;
	};

	class ReadException : public std::exception
	{
	  public:
		ReadException() : std::exception() {}
		virtual const char* what() const NOEXCEPT { return "read out of bounds"; }
	};

	class BinaryReader
	{
		Ref<BinaryView> m_view;
		BNBinaryReader* m_stream;

	  public:
		BinaryReader(BinaryView* data, BNEndianness endian = LittleEndian);
		~BinaryReader();

		BNEndianness GetEndianness() const;
		void SetEndianness(BNEndianness endian);

		void Read(void* dest, size_t len);
		DataBuffer Read(size_t len);
		template <typename T>
		T Read();
		template <typename T>
		std::vector<T> ReadVector(size_t count);
		std::string ReadString(size_t len);
		std::string ReadCString(size_t maxLength = -1);

		uint8_t Read8();
		uint16_t Read16();
		uint32_t Read32();
		uint64_t Read64();
		uint16_t ReadLE16();
		uint32_t ReadLE32();
		uint64_t ReadLE64();
		uint16_t ReadBE16();
		uint32_t ReadBE32();
		uint64_t ReadBE64();

		bool TryRead(void* dest, size_t len);
		bool TryRead(DataBuffer& dest, size_t len);
		bool TryReadString(std::string& dest, size_t len);
		bool TryRead8(uint8_t& result);
		bool TryRead16(uint16_t& result);
		bool TryRead32(uint32_t& result);
		bool TryRead64(uint64_t& result);
		bool TryReadLE16(uint16_t& result);
		bool TryReadLE32(uint32_t& result);
		bool TryReadLE64(uint64_t& result);
		bool TryReadBE16(uint16_t& result);
		bool TryReadBE32(uint32_t& result);
		bool TryReadBE64(uint64_t& result);

		uint64_t GetOffset() const;
		void Seek(uint64_t offset);
		void SeekRelative(int64_t offset);

		bool IsEndOfFile() const;
	};

	class WriteException : public std::exception
	{
	  public:
		WriteException() : std::exception() {}
		virtual const char* what() const NOEXCEPT { return "write out of bounds"; }
	};

	class BinaryWriter
	{
		Ref<BinaryView> m_view;
		BNBinaryWriter* m_stream;

	  public:
		BinaryWriter(BinaryView* data, BNEndianness endian = LittleEndian);
		~BinaryWriter();

		BNEndianness GetEndianness() const;
		void SetEndianness(BNEndianness endian);

		void Write(const void* src, size_t len);
		void Write(const DataBuffer& buf);
		void Write(const std::string& str);
		void Write8(uint8_t val);
		void Write16(uint16_t val);
		void Write32(uint32_t val);
		void Write64(uint64_t val);
		void WriteLE16(uint16_t val);
		void WriteLE32(uint32_t val);
		void WriteLE64(uint64_t val);
		void WriteBE16(uint16_t val);
		void WriteBE32(uint32_t val);
		void WriteBE64(uint64_t val);

		bool TryWrite(const void* src, size_t len);
		bool TryWrite(const DataBuffer& buf);
		bool TryWrite(const std::string& str);
		bool TryWrite8(uint8_t val);
		bool TryWrite16(uint16_t val);
		bool TryWrite32(uint32_t val);
		bool TryWrite64(uint64_t val);
		bool TryWriteLE16(uint16_t val);
		bool TryWriteLE32(uint32_t val);
		bool TryWriteLE64(uint64_t val);
		bool TryWriteBE16(uint16_t val);
		bool TryWriteBE32(uint32_t val);
		bool TryWriteBE64(uint64_t val);

		uint64_t GetOffset() const;
		void Seek(uint64_t offset);
		void SeekRelative(int64_t offset);
	};

	struct TransformParameter
	{
		std::string name, longName;
		size_t fixedLength;  // Variable length if zero
	};

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

	/*!
	    The Architecture class is the base class for all CPU architectures. This provides disassembly, assembly,
	    patching, and IL translation lifting for a given architecture.
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

		static void Register(Architecture* arch);
		static Ref<Architecture> GetByName(const std::string& name);
		static std::vector<Ref<Architecture>> GetList();

		std::string GetName() const;

		virtual BNEndianness GetEndianness() const = 0;
		virtual size_t GetAddressSize() const = 0;
		virtual size_t GetDefaultIntegerSize() const;

		virtual size_t GetInstructionAlignment() const;
		virtual size_t GetMaxInstructionLength() const;
		virtual size_t GetOpcodeDisplayLength() const;

		virtual Ref<Architecture> GetAssociatedArchitectureByAddress(uint64_t& addr);

		virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) = 0;
		virtual bool GetInstructionText(
		    const uint8_t* data, uint64_t addr, size_t& len, std::vector<InstructionTextToken>& result) = 0;

		/*! GetInstructionLowLevelIL
		    Translates an instruction at addr and appends it onto the LowLevelILFunction& il.
		    \param data pointer to the instruction data to be translated
		    \param addr address of the instruction data to be translated
		    \param len length of the instruction data to be translated
		    \param il the LowLevelILFunction which
		*/
		virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il);
		virtual std::string GetRegisterName(uint32_t reg);
		virtual std::string GetFlagName(uint32_t flag);
		virtual std::string GetFlagWriteTypeName(uint32_t flags);
		virtual std::string GetSemanticFlagClassName(uint32_t semClass);
		virtual std::string GetSemanticFlagGroupName(uint32_t semGroup);
		virtual std::vector<uint32_t> GetFullWidthRegisters();
		virtual std::vector<uint32_t> GetAllRegisters();
		virtual std::vector<uint32_t> GetAllFlags();
		virtual std::vector<uint32_t> GetAllFlagWriteTypes();
		virtual std::vector<uint32_t> GetAllSemanticFlagClasses();
		virtual std::vector<uint32_t> GetAllSemanticFlagGroups();
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
		virtual BNRegisterInfo GetRegisterInfo(uint32_t reg);
		virtual uint32_t GetStackPointerRegister();
		virtual uint32_t GetLinkRegister();
		virtual std::vector<uint32_t> GetGlobalRegisters();
		bool IsGlobalRegister(uint32_t reg);
		virtual std::vector<uint32_t> GetSystemRegisters();
		bool IsSystemRegister(uint32_t reg);
		std::vector<uint32_t> GetModifiedRegistersOnWrite(uint32_t reg);
		uint32_t GetRegisterByName(const std::string& name);

		virtual std::string GetRegisterStackName(uint32_t regStack);
		virtual std::vector<uint32_t> GetAllRegisterStacks();
		virtual BNRegisterStackInfo GetRegisterStackInfo(uint32_t regStack);
		uint32_t GetRegisterStackForRegister(uint32_t reg);

		virtual std::string GetIntrinsicName(uint32_t intrinsic);
		virtual std::vector<uint32_t> GetAllIntrinsics();
		virtual std::vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic);
		virtual std::vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic);

		virtual bool CanAssemble();
		virtual bool Assemble(const std::string& code, uint64_t addr, DataBuffer& result, std::string& errors);

		/*! IsNeverBranchPatchAvailable returns true if the instruction at addr can be patched to never branch.
		    This is used in the UI to determine if "never branch" should be displayed in the right-click context
		    menu when right-clicking on an instruction.
		    \param arch the architecture of the instruction
		    \param addr the address of the instruction in question
		*/
		virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! IsAlwaysBranchPatchAvailable returns true if the instruction at addr can be patched to always branch.
		    This is used in the UI to determine if "always branch" should be displayed in the right-click context
		    menu when right-clicking on an instruction.
		    \param arch the architecture of the instruction
		    \param addr the address of the instruction in question
		*/
		virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! IsInvertBranchPatchAvailable returns true if the instruction at addr can be patched to invert the branch.
		    This is used in the UI to determine if "invert branch" should be displayed in the right-click context
		    menu when right-clicking on an instruction.
		    \param arch the architecture of the instruction
		    \param addr the address of the instruction in question
		*/
		virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! IsSkipAndReturnZeroPatchAvailable returns true if the instruction at addr is a call that can be patched to
		    return zero. This is used in the UI to determine if "skip and return zero" should be displayed in the
		    right-click context menu when right-clicking on an instruction.
		    \param arch the architecture of the instruction
		    \param addr the address of the instruction in question
		*/
		virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! IsSkipAndReturnValuePatchAvailable returns true if the instruction at addr is a call that can be patched to
		    return a value. This is used in the UI to determine if "skip and return value" should be displayed in the
		    right-click context menu when right-clicking on an instruction.
		    \param arch the architecture of the instruction
		    \param addr the address of the instruction in question
		*/
		virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! ConvertToNop converts the instruction at addr to a no-operation instruction
		    \param arch the architecture of the instruction
		    \param addr the address of the instruction in question
		*/
		virtual bool ConvertToNop(uint8_t* data, uint64_t addr, size_t len);

		/*! AlwaysBranch converts the conditional branch instruction at addr to an unconditional branch. This is called
		    when the right-click context menu item "always branch" is selected in the UI.
		    \param arch the architecture of the instruction
		    \param addr the address of the instruction in question
		*/
		virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len);

		/*! InvertBranch converts the conditional branch instruction at addr to its invert. This is called
		    when the right-click context menu item "invert branch" is selected in the UI.
		    \param arch the architecture of the instruction
		    \param addr the address of the instruction in question
		*/
		virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len);

		/*! SkipAndReturnValue converts the call instruction at addr to an instruction that simulates that call
		    returning a value. This is called when the right-click context menu item "skip and return value" is selected
		    in the UI.
		    \param arch the architecture of the instruction
		    \param addr the address of the instruction in question
		*/
		virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value);

		void RegisterFunctionRecognizer(FunctionRecognizer* recog);
		void RegisterRelocationHandler(const std::string& viewName, RelocationHandler* handler);
		Ref<RelocationHandler> GetRelocationHandler(const std::string& viewName);

		bool IsBinaryViewTypeConstantDefined(const std::string& type, const std::string& name);
		uint64_t GetBinaryViewTypeConstant(const std::string& type, const std::string& name, uint64_t defaultValue = 0);
		void SetBinaryViewTypeConstant(const std::string& type, const std::string& name, uint64_t value);

		void RegisterCallingConvention(CallingConvention* cc);
		std::vector<Ref<CallingConvention>> GetCallingConventions();
		Ref<CallingConvention> GetCallingConventionByName(const std::string& name);

		void SetDefaultCallingConvention(CallingConvention* cc);
		void SetCdeclCallingConvention(CallingConvention* cc);
		void SetStdcallCallingConvention(CallingConvention* cc);
		void SetFastcallCallingConvention(CallingConvention* cc);
		Ref<CallingConvention> GetDefaultCallingConvention();
		Ref<CallingConvention> GetCdeclCallingConvention();
		Ref<CallingConvention> GetStdcallCallingConvention();
		Ref<CallingConvention> GetFastcallCallingConvention();
		Ref<Platform> GetStandalonePlatform();

		void AddArchitectureRedirection(Architecture* from, Architecture* to);
	};

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

	struct TypeParserResult
	{
		std::vector<ParsedType> types;
		std::vector<ParsedType> variables;
		std::vector<ParsedType> functions;
	};

	struct TypeParserError
	{
		BNTypeParserErrorSeverity severity;
		std::string message;
		std::string fileName;
		uint64_t line;
		uint64_t column;
	};

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

	struct StructureMember
	{
		Ref<Type> type;
		std::string name;
		uint64_t offset;
		BNMemberAccess access;
		BNMemberScope scope;
	};

	class Structure : public CoreRefCountObject<BNStructure, BNNewStructureReference, BNFreeStructure>
	{
	  public:
		Structure(BNStructure* s);

		std::vector<StructureMember> GetMembers() const;
		bool GetMemberByName(const std::string& name, StructureMember& result) const;
		bool GetMemberAtOffset(int64_t offset, StructureMember& result) const;
		bool GetMemberAtOffset(int64_t offset, StructureMember& result, size_t& idx) const;
		uint64_t GetWidth() const;
		size_t GetAlignment() const;
		bool IsPacked() const;
		bool IsUnion() const;
		BNStructureVariant GetStructureType() const;

		Ref<Structure> WithReplacedStructure(Structure* from, Structure* to);
		Ref<Structure> WithReplacedEnumeration(Enumeration* from, Enumeration* to);
		Ref<Structure> WithReplacedNamedTypeReference(NamedTypeReference* from, NamedTypeReference* to);
	};

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

		    \return One of: ClassStructureType, StructStructureType, UnionStructureType
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

	struct EnumerationMember
	{
		std::string name;
		uint64_t value;
		bool isDefault;
	};

	class Enumeration : public CoreRefCountObject<BNEnumeration, BNNewEnumerationReference, BNFreeEnumeration>
	{
	  public:
		Enumeration(BNEnumeration* e);

		std::vector<EnumerationMember> GetMembers() const;
	};

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

	class AnalysisContext :
	    public CoreRefCountObject<BNAnalysisContext, BNNewAnalysisContextReference, BNFreeAnalysisContext>
	{
		std::unique_ptr<Json::CharReader> m_reader;
		Json::StreamWriterBuilder m_builder;

	  public:
		AnalysisContext(BNAnalysisContext* analysisContext);
		virtual ~AnalysisContext();

		Ref<Function> GetFunction();
		Ref<LowLevelILFunction> GetLowLevelILFunction();
		Ref<MediumLevelILFunction> GetMediumLevelILFunction();
		Ref<HighLevelILFunction> GetHighLevelILFunction();

		void SetBasicBlockList(std::vector<Ref<BasicBlock>> basicBlocks);
		void SetLiftedILFunction(Ref<LowLevelILFunction> liftedIL);
		void SetLowLevelILFunction(Ref<LowLevelILFunction> lowLevelIL);
		void SetMediumLevelILFunction(Ref<MediumLevelILFunction> mediumLevelIL);
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

	class Activity : public CoreRefCountObject<BNActivity, BNNewActivityReference, BNFreeActivity>
	{
	  protected:
		std::function<void(Ref<AnalysisContext> analysisContext)> m_action;

		static void Run(void* ctxt, BNAnalysisContext* analysisContext);

	  public:
		Activity(const std::string& name, const std::function<void(Ref<AnalysisContext>)>& action);
		Activity(BNActivity* activity);
		virtual ~Activity();

		std::string GetName() const;
	};

	class Workflow : public CoreRefCountObject<BNWorkflow, BNNewWorkflowReference, BNFreeWorkflow>
	{
	  public:
		Workflow(const std::string& name = "");
		Workflow(BNWorkflow* workflow);
		virtual ~Workflow() {}

		static std::vector<Ref<Workflow>> GetList();
		static Ref<Workflow> Instance(const std::string& name = "");
		static bool RegisterWorkflow(Ref<Workflow> workflow, const std::string& description = "");

		Ref<Workflow> Clone(const std::string& name, const std::string& activity = "");
		bool RegisterActivity(Ref<Activity> activity, const std::string& description = "");
		bool RegisterActivity(Ref<Activity> activity, std::initializer_list<const char*> initializer)
		{
			return RegisterActivity(activity, std::vector<std::string>(initializer.begin(), initializer.end()));
		}
		bool RegisterActivity(
		    Ref<Activity> activity, const std::vector<std::string>& subactivities, const std::string& description = "");

		bool Contains(const std::string& activity);
		std::string GetConfiguration(const std::string& activity = "");
		std::string GetName() const;
		bool IsRegistered() const;
		size_t Size() const;

		Ref<Activity> GetActivity(const std::string& activity);
		std::vector<std::string> GetActivityRoots(const std::string& activity = "");
		std::vector<std::string> GetSubactivities(const std::string& activity = "", bool immediate = true);
		bool AssignSubactivities(const std::string& activity, const std::vector<std::string>& subactivities = {});
		bool Clear();
		bool Insert(const std::string& activity, const std::string& newActivity);
		bool Insert(const std::string& activity, const std::vector<std::string>& activities);
		bool Remove(const std::string& activity);
		bool Replace(const std::string& activity, const std::string& newActivity);

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

	struct BasicBlockEdge
	{
		BNBranchType type;
		Ref<BasicBlock> target;
		bool backEdge;
		bool fallThrough;
	};

	class BasicBlock : public CoreRefCountObject<BNBasicBlock, BNNewBasicBlockReference, BNFreeBasicBlock>
	{
	  public:
		BasicBlock(BNBasicBlock* block);

		Ref<Function> GetFunction() const;
		Ref<Architecture> GetArchitecture() const;

		uint64_t GetStart() const;
		uint64_t GetEnd() const;
		uint64_t GetLength() const;

		size_t GetIndex() const;

		std::vector<BasicBlockEdge> GetOutgoingEdges() const;
		std::vector<BasicBlockEdge> GetIncomingEdges() const;
		bool HasUndeterminedOutgoingEdges() const;
		bool CanExit() const;
		void SetCanExit(bool value);

		std::set<Ref<BasicBlock>> GetDominators(bool post = false) const;
		std::set<Ref<BasicBlock>> GetStrictDominators(bool post = false) const;
		Ref<BasicBlock> GetImmediateDominator(bool post = false) const;
		std::set<Ref<BasicBlock>> GetDominatorTreeChildren(bool post = false) const;
		std::set<Ref<BasicBlock>> GetDominanceFrontier(bool post = false) const;
		static std::set<Ref<BasicBlock>> GetIteratedDominanceFrontier(const std::set<Ref<BasicBlock>>& blocks);

		void MarkRecentUse();

		std::vector<std::vector<InstructionTextToken>> GetAnnotations();

		std::vector<DisassemblyTextLine> GetDisassemblyText(DisassemblySettings* settings);

		BNHighlightColor GetBasicBlockHighlight();
		void SetAutoBasicBlockHighlight(BNHighlightColor color);
		void SetAutoBasicBlockHighlight(BNHighlightStandardColor color, uint8_t alpha = 255);
		void SetAutoBasicBlockHighlight(
		    BNHighlightStandardColor color, BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha = 255);
		void SetAutoBasicBlockHighlight(uint8_t r, uint8_t g, uint8_t b, uint8_t alpha = 255);
		void SetUserBasicBlockHighlight(BNHighlightColor color);
		void SetUserBasicBlockHighlight(BNHighlightStandardColor color, uint8_t alpha = 255);
		void SetUserBasicBlockHighlight(
		    BNHighlightStandardColor color, BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha = 255);
		void SetUserBasicBlockHighlight(uint8_t r, uint8_t g, uint8_t b, uint8_t alpha = 255);

		static bool IsBackEdge(BasicBlock* source, BasicBlock* target);

		bool IsILBlock() const;
		bool IsLowLevelILBlock() const;
		bool IsMediumLevelILBlock() const;
		Ref<LowLevelILFunction> GetLowLevelILFunction() const;
		Ref<MediumLevelILFunction> GetMediumLevelILFunction() const;
		Ref<HighLevelILFunction> GetHighLevelILFunction() const;

		bool GetInstructionContainingAddress(uint64_t addr, uint64_t* start);
		Ref<BasicBlock> GetSourceBlock() const;
	};

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

	struct StackVariableReference
	{
		uint32_t sourceOperand;
		Confidence<Ref<Type>> type;
		std::string name;
		Variable var;
		int64_t referencedOffset;
		size_t size;
	};

	struct IndirectBranchInfo
	{
		Ref<Architecture> sourceArch;
		uint64_t sourceAddr;
		Ref<Architecture> destArch;
		uint64_t destAddr;
		bool autoDefined;
	};

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

	struct LookupTableEntry
	{
		std::vector<int64_t> fromValues;
		int64_t toValue;
	};

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
	struct SSAVariable;

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

		void AddUserCodeReference(Architecture* fromArch, uint64_t fromAddr, uint64_t toAddr);
		void RemoveUserCodeReference(Architecture* fromArch, uint64_t fromAddr, uint64_t toAddr);
		void AddUserTypeReference(Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name);
		void RemoveUserTypeReference(Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name);
		void AddUserTypeFieldReference(
		    Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name, uint64_t offset, size_t size = 0);
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

		Ref<LowLevelILFunction> GetLiftedIL() const;
		Ref<LowLevelILFunction> GetLiftedILIfAvailable() const;
		size_t GetLiftedILForInstruction(Architecture* arch, uint64_t addr);
		std::set<size_t> GetLiftedILInstructionsForAddress(Architecture* arch, uint64_t addr);
		std::set<size_t> GetLiftedILFlagUsesForDefinition(size_t i, uint32_t flag);
		std::set<size_t> GetLiftedILFlagDefinitionsForUse(size_t i, uint32_t flag);
		std::set<uint32_t> GetFlagsReadByLiftedILInstruction(size_t i);
		std::set<uint32_t> GetFlagsWrittenByLiftedILInstruction(size_t i);

		Ref<MediumLevelILFunction> GetMediumLevelIL() const;
		Ref<MediumLevelILFunction> GetMediumLevelILIfAvailable() const;
		Ref<MediumLevelILFunction> GetMappedMediumLevelIL() const;
		Ref<MediumLevelILFunction> GetMappedMediumLevelILIfAvailable() const;
		Ref<HighLevelILFunction> GetHighLevelIL() const;
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

		bool IsFunctionTooLarge();
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

		std::string GetGotoLabelName(uint64_t labelId);
		void SetGotoLabelName(uint64_t labelId, const std::string& name);

		BNDeadStoreElimination GetVariableDeadStoreElimination(const Variable& var);
		void SetVariableDeadStoreElimination(const Variable& var, BNDeadStoreElimination mode);

		uint64_t GetHighestAddress();
		uint64_t GetLowestAddress();
		std::vector<BNAddressRange> GetAddressRanges();

		bool GetInstructionContainingAddress(Architecture* arch, uint64_t addr, uint64_t* start);
	};

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

	struct FlowGraphEdge
	{
		BNBranchType type;
		Ref<FlowGraphNode> target;
		std::vector<BNPoint> points;
		bool backEdge;
		BNEdgeStyle style;
	};

	class FlowGraphNode : public CoreRefCountObject<BNFlowGraphNode, BNNewFlowGraphNodeReference, BNFreeFlowGraphNode>
	{
		std::vector<DisassemblyTextLine> m_cachedLines;
		std::vector<FlowGraphEdge> m_cachedEdges, m_cachedIncomingEdges;
		bool m_cachedLinesValid, m_cachedEdgesValid, m_cachedIncomingEdgesValid;

	  public:
		FlowGraphNode(FlowGraph* graph);
		FlowGraphNode(BNFlowGraphNode* node);

		Ref<FlowGraph> GetGraph() const;
		Ref<BasicBlock> GetBasicBlock() const;
		void SetBasicBlock(BasicBlock* block);
		int GetX() const;
		int GetY() const;
		int GetWidth() const;
		int GetHeight() const;

		const std::vector<DisassemblyTextLine>& GetLines();
		void SetLines(const std::vector<DisassemblyTextLine>& lines);
		const std::vector<FlowGraphEdge>& GetOutgoingEdges();
		const std::vector<FlowGraphEdge>& GetIncomingEdges();
		void AddOutgoingEdge(BNBranchType type, FlowGraphNode* target, BNEdgeStyle edgeStyle = BNEdgeStyle());

		BNHighlightColor GetHighlight() const;
		void SetHighlight(const BNHighlightColor& color);

		bool IsValidForGraph(FlowGraph* graph) const;
	};

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

		Ref<Function> GetFunction() const;
		Ref<BinaryView> GetView() const;
		void SetFunction(Function* func);
		void SetView(BinaryView* view);

		int GetHorizontalNodeMargin() const;
		int GetVerticalNodeMargin() const;
		void SetNodeMargins(int horiz, int vert);

		Ref<FlowGraphLayoutRequest> StartLayout(const std::function<void()>& func);
		bool IsLayoutComplete();

		std::vector<Ref<FlowGraphNode>> GetNodes();
		Ref<FlowGraphNode> GetNode(size_t i);
		bool HasNodes() const;
		size_t AddNode(FlowGraphNode* node);

		int GetWidth() const;
		int GetHeight() const;
		std::vector<Ref<FlowGraphNode>> GetNodesInRegion(int left, int top, int right, int bottom);

		bool IsILGraph() const;
		bool IsLowLevelILGraph() const;
		bool IsMediumLevelILGraph() const;
		bool IsHighLevelILGraph() const;
		Ref<LowLevelILFunction> GetLowLevelILFunction() const;
		Ref<MediumLevelILFunction> GetMediumLevelILFunction() const;
		Ref<HighLevelILFunction> GetHighLevelILFunction() const;
		void SetLowLevelILFunction(LowLevelILFunction* func);
		void SetMediumLevelILFunction(MediumLevelILFunction* func);
		void SetHighLevelILFunction(HighLevelILFunction* func);

		void Show(const std::string& title);

		virtual bool HasUpdates() const;

		virtual Ref<FlowGraph> Update();

		void SetOption(BNFlowGraphOption option, bool value = true);
		bool IsOptionSet(BNFlowGraphOption option);
	};

	class CoreFlowGraph : public FlowGraph
	{
	  public:
		CoreFlowGraph(BNFlowGraph* graph);
		virtual bool HasUpdates() const override;
		virtual Ref<FlowGraph> Update() override;
	};

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

	struct MediumLevelILLabel : public BNMediumLevelILLabel
	{
		MediumLevelILLabel();
	};

	struct MediumLevelILInstruction;

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

		static bool IsConstantType(BNMediumLevelILOperation op)
		{
			return op == MLIL_CONST || op == MLIL_CONST_PTR || op == MLIL_EXTERN_PTR;
		}

		Ref<FlowGraph> CreateFunctionGraph(DisassemblySettings* settings = nullptr);
	};

	struct HighLevelILInstruction;

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
	 */
	struct UpdateVersion
	{
		std::string version;
		std::string notes;
		time_t time;

		static std::vector<UpdateVersion> GetChannelVersions(const std::string& channel);
	};

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

		static void Register(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view)>& action);
		static void Register(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view)>& action, const std::function<bool(BinaryView* view)>& isValid);
		static void RegisterForAddress(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr)>& action);
		static void RegisterForAddress(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr)>& action,
		    const std::function<bool(BinaryView* view, uint64_t addr)>& isValid);
		static void RegisterForRange(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr, uint64_t len)>& action);
		static void RegisterForRange(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr, uint64_t len)>& action,
		    const std::function<bool(BinaryView* view, uint64_t addr, uint64_t len)>& isValid);
		static void RegisterForFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, Function* func)>& action);
		static void RegisterForFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, Function* func)>& action,
		    const std::function<bool(BinaryView* view, Function* func)>& isValid);
		static void RegisterForLowLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, LowLevelILFunction* func)>& action);
		static void RegisterForLowLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, LowLevelILFunction* func)>& action,
		    const std::function<bool(BinaryView* view, LowLevelILFunction* func)>& isValid);
		static void RegisterForLowLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const LowLevelILInstruction& instr)>& action);
		static void RegisterForLowLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const LowLevelILInstruction& instr)>& action,
		    const std::function<bool(BinaryView* view, const LowLevelILInstruction& instr)>& isValid);
		static void RegisterForMediumLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, MediumLevelILFunction* func)>& action);
		static void RegisterForMediumLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, MediumLevelILFunction* func)>& action,
		    const std::function<bool(BinaryView* view, MediumLevelILFunction* func)>& isValid);
		static void RegisterForMediumLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const MediumLevelILInstruction& instr)>& action);
		static void RegisterForMediumLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const MediumLevelILInstruction& instr)>& action,
		    const std::function<bool(BinaryView* view, const MediumLevelILInstruction& instr)>& isValid);
		static void RegisterForHighLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, HighLevelILFunction* func)>& action);
		static void RegisterForHighLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, HighLevelILFunction* func)>& action,
		    const std::function<bool(BinaryView* view, HighLevelILFunction* func)>& isValid);
		static void RegisterForHighLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const HighLevelILInstruction& instr)>& action);
		static void RegisterForHighLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const HighLevelILInstruction& instr)>& action,
		    const std::function<bool(BinaryView* view, const HighLevelILInstruction& instr)>& isValid);

		static std::vector<PluginCommand> GetList();
		static std::vector<PluginCommand> GetValidList(const PluginCommandContext& ctxt);

		std::string GetName() const { return m_command.name; }
		std::string GetDescription() const { return m_command.description; }
		BNPluginCommandType GetType() const { return m_command.type; }
		const BNPluginCommand* GetObject() const { return &m_command; }

		bool IsValid(const PluginCommandContext& ctxt) const;
		void Execute(const PluginCommandContext& ctxt) const;
	};

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
	 */
	class Platform : public CoreRefCountObject<BNPlatform, BNNewPlatformReference, BNFreePlatform>
	{
	  protected:
		Platform(Architecture* arch, const std::string& name);
		Platform(Architecture* arch, const std::string& name, const std::string& typeFile,
		    const std::vector<std::string>& includeDirs = std::vector<std::string>());

	  public:
		Platform(BNPlatform* platform);

		Ref<Architecture> GetArchitecture() const;
		std::string GetName() const;

		static void Register(const std::string& os, Platform* platform);
		static Ref<Platform> GetByName(const std::string& name);
		static std::vector<Ref<Platform>> GetList();
		static std::vector<Ref<Platform>> GetList(Architecture* arch);
		static std::vector<Ref<Platform>> GetList(const std::string& os);
		static std::vector<Ref<Platform>> GetList(const std::string& os, Architecture* arch);
		static std::vector<std::string> GetOSList();

		Ref<CallingConvention> GetDefaultCallingConvention() const;
		Ref<CallingConvention> GetCdeclCallingConvention() const;
		Ref<CallingConvention> GetStdcallCallingConvention() const;
		Ref<CallingConvention> GetFastcallCallingConvention() const;
		std::vector<Ref<CallingConvention>> GetCallingConventions() const;
		Ref<CallingConvention> GetSystemCallConvention() const;

		void RegisterCallingConvention(CallingConvention* cc);
		void RegisterDefaultCallingConvention(CallingConvention* cc);
		void RegisterCdeclCallingConvention(CallingConvention* cc);
		void RegisterStdcallCallingConvention(CallingConvention* cc);
		void RegisterFastcallCallingConvention(CallingConvention* cc);
		void SetSystemCallConvention(CallingConvention* cc);

		Ref<Platform> GetRelatedPlatform(Architecture* arch);
		void AddRelatedPlatform(Architecture* arch, Platform* platform);
		Ref<Platform> GetAssociatedPlatformByAddress(uint64_t& addr);

		std::map<QualifiedName, Ref<Type>> GetTypes();
		std::map<QualifiedName, Ref<Type>> GetVariables();
		std::map<QualifiedName, Ref<Type>> GetFunctions();
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

		bool ParseTypesFromSource(const std::string& source, const std::string& fileName,
		    std::map<QualifiedName, Ref<Type>>& types, std::map<QualifiedName, Ref<Type>>& variables,
		    std::map<QualifiedName, Ref<Type>>& functions, std::string& errors,
		    const std::vector<std::string>& includeDirs = std::vector<std::string>(),
		    const std::string& autoTypeSource = "");
		bool ParseTypesFromSourceFile(const std::string& fileName, std::map<QualifiedName, Ref<Type>>& types,
		    std::map<QualifiedName, Ref<Type>>& variables, std::map<QualifiedName, Ref<Type>>& functions,
		    std::string& errors, const std::vector<std::string>& includeDirs = std::vector<std::string>(),
		    const std::string& autoTypeSource = "");
	};

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

	class MainThreadAction :
	    public CoreRefCountObject<BNMainThreadAction, BNNewMainThreadActionReference, BNFreeMainThreadAction>
	{
	  public:
		MainThreadAction(BNMainThreadAction* action);
		void Execute();
		bool IsDone() const;
		void Wait();
	};

	class MainThreadActionHandler
	{
	  public:
		virtual void AddMainThreadAction(MainThreadAction* action) = 0;
	};

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
	};

	typedef BNPluginOrigin PluginOrigin;
	typedef BNPluginStatus PluginStatus;
	typedef BNPluginType PluginType;

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

	class Settings : public CoreRefCountObject<BNSettings, BNNewSettingsReference, BNFreeSettings>
	{
		std::string m_instanceId;

		Settings() = delete;
		Settings(const std::string& m_instanceId);

	  public:
		Settings(BNSettings* settings);
		static Ref<Settings> Instance(const std::string& schemaId = "");
		virtual ~Settings() {}

		void SetResourceId(const std::string& resourceId = "");

		bool RegisterGroup(const std::string& group, const std::string& title);
		bool RegisterSetting(const std::string& key, const std::string& properties);
		bool Contains(const std::string& key);
		bool IsEmpty();
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

		template <typename T>
		T Get(const std::string& key, Ref<BinaryView> view = nullptr, BNSettingsScope* scope = nullptr);
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

	typedef BNMetadataType MetadataType;

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

	class DataRendererContainer
	{
	  public:
		static void RegisterGenericDataRenderer(DataRenderer* renderer);
		static void RegisterTypeSpecificDataRenderer(DataRenderer* renderer);
	};

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

	struct DebugFunctionInfo
	{
		std::string shortName;
		std::string fullName;
		std::string rawName;
		uint64_t address;
		Ref<Type> returnType;
		std::vector<std::tuple<std::string, Ref<Type>>> parameters;
		bool variableParameters;
		Ref<CallingConvention> callingConvention;
		Ref<Platform> platform;

		DebugFunctionInfo(std::string shortName, std::string fullName, std::string rawName, uint64_t address,
		    Ref<Type> returnType, std::vector<std::tuple<std::string, Ref<Type>>> parameters, bool variableParameters,
		    Ref<CallingConvention> callingConvention, Ref<Platform> platform) :
		    shortName(shortName),
		    fullName(fullName), rawName(rawName), address(address), returnType(returnType), parameters(parameters),
		    variableParameters(variableParameters), callingConvention(callingConvention), platform(platform)
		{}
	};

	class DebugInfo : public CoreRefCountObject<BNDebugInfo, BNNewDebugInfoReference, BNFreeDebugInfoReference>
	{
	  public:
		DebugInfo(BNDebugInfo* debugInfo);

		std::vector<NameAndType> GetTypes(const std::string& parserName = "");
		std::vector<DebugFunctionInfo> GetFunctions(const std::string& parserName = "");
		std::vector<DataVariableAndName> GetDataVariables(const std::string& parserName = "");

		bool AddType(const std::string& name, Ref<Type> type);
		bool AddFunction(const DebugFunctionInfo& function);
		bool AddDataVariable(uint64_t address, Ref<Type> type, const std::string& name = "");
	};

	class DebugInfoParser :
	    public CoreRefCountObject<BNDebugInfoParser, BNNewDebugInfoParserReference, BNFreeDebugInfoParserReference>
	{
	  public:
		DebugInfoParser(BNDebugInfoParser* parser);

		static Ref<DebugInfoParser> GetByName(const std::string& name);
		static std::vector<Ref<DebugInfoParser>> GetList();
		static std::vector<Ref<DebugInfoParser>> GetListForView(const Ref<BinaryView> data);

		std::string GetName() const;
		Ref<DebugInfo> Parse(Ref<BinaryView> view, Ref<DebugInfo> existingDebugInfo = nullptr) const;

		bool IsValidForView(const Ref<BinaryView> view) const;
	};

	class CustomDebugInfoParser : public DebugInfoParser
	{
		static bool IsValidCallback(void* ctxt, BNBinaryView* view);
		static void ParseCallback(void* ctxt, BNDebugInfo* debugInfo, BNBinaryView* view);
		BNDebugInfoParser* Register(const std::string& name);

	  public:
		CustomDebugInfoParser(const std::string& name);
		virtual ~CustomDebugInfoParser() {}

		virtual bool IsValid(Ref<BinaryView>) = 0;
		virtual void ParseInfo(Ref<DebugInfo>, Ref<BinaryView>) = 0;
	};

	/*!
	    Class for storing secrets (e.g. tokens) in a system-specific manner
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
		/*!
		    Check if data for a specific key exists, but do not retrieve it
		    \param key Key for data
		    \return True if data exists
		 */
		virtual bool HasData(const std::string& key) = 0;
		/*!
		    Retrieve data for the given key, if it exists
		    \param key Key for data
		    \return Optional with data, if it exists, or empty optional if it does not exist
		            or otherwise could not be retrieved.
		 */
		virtual std::optional<std::string> GetData(const std::string& key) = 0;
		/*!
		    Store data with the given key
		    \param key Key for data
		    \param data Data to store
		    \return True if the data was stored
		 */
		virtual bool StoreData(const std::string& key, const std::string& data) = 0;
		/*!
		    Delete stored data with the given key
		    \param key Key for data
		    \return True if it was deleted
		 */
		virtual bool DeleteData(const std::string& key) = 0;

		/*!
		    Retrieve the list of providers
		    \return A list of registered providers
		 */
		static std::vector<Ref<SecretsProvider>> GetList();
		/*!
		    Retrieve a provider by name
		    \param name Name of provider
		    \return Provider object, if one with the given name is regestered, or nullptr if not
		 */
		static Ref<SecretsProvider> GetByName(const std::string& name);
		/*!
		    Register a new provider
		    \param provider New provider to register
		 */
		static void Register(SecretsProvider* provider);
	};

	class CoreSecretsProvider : public SecretsProvider
	{
	  public:
		CoreSecretsProvider(BNSecretsProvider* provider);

		virtual bool HasData(const std::string& key) override;
		virtual std::optional<std::string> GetData(const std::string& key) override;
		virtual bool StoreData(const std::string& key, const std::string& data) override;
		virtual bool DeleteData(const std::string& key) override;
	};
}  // namespace BinaryNinja
