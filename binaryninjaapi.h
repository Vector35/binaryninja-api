// Copyright (c) 2015-2017 Vector 35 LLC
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
#include <memory>
#include "binaryninjacore.h"
#include "json/json.h"

#ifdef _MSC_VER
#define NOEXCEPT
#else
#define NOEXCEPT noexcept
#endif


namespace BinaryNinja
{
	class RefCountObject
	{
	public:
		int m_refs;
		RefCountObject(): m_refs(0) {}
		virtual ~RefCountObject() {}

		RefCountObject* GetObject() { return this; }

		void AddRef()
		{
#ifdef WIN32
			InterlockedIncrement((LONG*)&m_refs);
#else
			__sync_fetch_and_add(&m_refs, 1);
#endif
		}

		void Release()
		{
#ifdef WIN32
			if (InterlockedDecrement((LONG*)&m_refs) == 0)
				delete this;
#else
			if (__sync_fetch_and_add(&m_refs, -1) == 1)
				delete this;
#endif
		}
	};

	template <class T, T* (*AddObjectReference)(T*), void (*FreeObjectReference)(T*)>
	class CoreRefCountObject
	{
		void AddRefInternal()
		{
#ifdef WIN32
			InterlockedIncrement((LONG*)&m_refs);
#else
			__sync_fetch_and_add(&m_refs, 1);
#endif
		}

		void ReleaseInternal()
		{
#ifdef WIN32
			if (InterlockedDecrement((LONG*)&m_refs) == 0)
				delete this;
#else
			if (__sync_fetch_and_add(&m_refs, -1) == 1)
				delete this;
#endif
		}

	public:
		int m_refs;
		T* m_object;
		CoreRefCountObject(): m_refs(0), m_object(nullptr) {}
		virtual ~CoreRefCountObject() {}

		T* GetObject() const { return m_object; }

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

		void AddRefForRegistration()
		{
			AddRefInternal();
		}

		void ReleaseForRegistration()
		{
			m_object = nullptr;
			ReleaseInternal();
		}
	};

	template <class T>
	class StaticCoreRefCountObject
	{
		void AddRefInternal()
		{
#ifdef WIN32
			InterlockedIncrement((LONG*)&m_refs);
#else
			__sync_fetch_and_add(&m_refs, 1);
#endif
		}

		void ReleaseInternal()
		{
#ifdef WIN32
			if (InterlockedDecrement((LONG*)&m_refs) == 0)
				delete this;
#else
			if (__sync_fetch_and_add(&m_refs, -1) == 1)
				delete this;
#endif
		}

	public:
		int m_refs;
		T* m_object;
		StaticCoreRefCountObject(): m_refs(0), m_object(nullptr) {}
		virtual ~StaticCoreRefCountObject() {}

		T* GetObject() const { return m_object; }

		void AddRef()
		{
			AddRefInternal();
		}

		void Release()
		{
			ReleaseInternal();
		}

		void AddRefForRegistration()
		{
			AddRefInternal();
		}
	};

	template <class T>
	class Ref
	{
		T* m_obj;

	public:
		Ref<T>(): m_obj(NULL)
		{
		}

		Ref<T>(T* obj): m_obj(obj)
		{
			if (m_obj)
				m_obj->AddRef();
		}

		Ref<T>(const Ref<T>& obj): m_obj(obj.m_obj)
		{
			if (m_obj)
				m_obj->AddRef();
		}

		~Ref<T>()
		{
			if (m_obj)
				m_obj->Release();
		}

		Ref<T>& operator=(const Ref<T>& obj)
		{
			T* oldObj = m_obj;
			m_obj = obj.m_obj;
			if (m_obj)
				m_obj->AddRef();
			if (oldObj)
				oldObj->Release();
			return *this;
		}

		Ref<T>& operator=(T* obj)
		{
			T* oldObj = m_obj;
			m_obj = obj;
			if (m_obj)
				m_obj->AddRef();
			if (oldObj)
				oldObj->Release();
			return *this;
		}

		operator T*() const
		{
			return m_obj;
		}

		T* operator->() const
		{
			return m_obj;
		}

		T& operator*() const
		{
			return *m_obj;
		}

		bool operator!() const
		{
			return m_obj == NULL;
		}

		bool operator==(const T* obj) const
		{
			return m_obj->GetObject() == obj->GetObject();
		}

		bool operator==(const Ref<T>& obj) const
		{
			return m_obj->GetObject() == obj.m_obj->GetObject();
		}

		bool operator!=(const T* obj) const
		{
			return m_obj->GetObject() != obj->GetObject();
		}

		bool operator!=(const Ref<T>& obj) const
		{
			return m_obj->GetObject() != obj.m_obj->GetObject();
		}

		bool operator<(const T* obj) const
		{
			return m_obj->GetObject() < obj->GetObject();
		}

		bool operator<(const Ref<T>& obj) const
		{
			return m_obj->GetObject() < obj.m_obj->GetObject();
		}

		T* GetPtr() const
		{
			return m_obj;
		}
	};

	class ConfidenceBase
	{
	protected:
		uint8_t m_confidence;

	public:
		ConfidenceBase(): m_confidence(0)
		{
		}

		ConfidenceBase(uint8_t conf): m_confidence(conf)
		{
		}

		static uint8_t Combine(uint8_t a, uint8_t b)
		{
			uint8_t result = (uint8_t)(((uint32_t)a * (uint32_t)b) / BN_FULL_CONFIDENCE);
			if ((a >= BN_MINIMUM_CONFIDENCE) && (b >= BN_MINIMUM_CONFIDENCE) &&
				(result < BN_MINIMUM_CONFIDENCE))
				result = BN_MINIMUM_CONFIDENCE;
			return result;
		}

		uint8_t GetConfidence() const { return m_confidence; }
		uint8_t GetCombinedConfidence(uint8_t base) const { return Combine(m_confidence, base); }
		void SetConfidence(uint8_t conf) { m_confidence = conf; }
		bool IsUnknown() const { return m_confidence == 0; }
	};

	template <class T>
	class Confidence: public ConfidenceBase
	{
		T m_value;

	public:
		Confidence()
		{
		}

		Confidence(const T& value): ConfidenceBase(BN_FULL_CONFIDENCE), m_value(value)
		{
		}

		Confidence(const T& value, uint8_t conf): ConfidenceBase(conf), m_value(value)
		{
		}

		Confidence(const Confidence<T>& v): ConfidenceBase(v.m_confidence), m_value(v.m_value)
		{
		}

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

		bool operator!=(const Confidence<T>& a) const
		{
			return !(*this == a);
		}
	};

	template <class T>
	class Confidence<Ref<T>>: public ConfidenceBase
	{
		Ref<T> m_value;

	public:
		Confidence()
		{
		}

		Confidence(T* value): ConfidenceBase(value ? BN_FULL_CONFIDENCE : 0), m_value(value)
		{
		}

		Confidence(T* value, uint8_t conf): ConfidenceBase(conf), m_value(value)
		{
		}

		Confidence(const Ref<T>& value): ConfidenceBase(value ? BN_FULL_CONFIDENCE : 0), m_value(value)
		{
		}

		Confidence(const Ref<T>& value, uint8_t conf): ConfidenceBase(conf), m_value(value)
		{
		}

		Confidence(const Confidence<Ref<T>>& v): ConfidenceBase(v.m_confidence), m_value(v.m_value)
		{
		}

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

		bool operator!=(const Confidence<Ref<T>>& a) const
		{
			return !(*this == a);
		}
	};

	class LogListener
	{
		static void LogMessageCallback(void* ctxt, BNLogLevel level, const char* msg);
		static void CloseLogCallback(void* ctxt);
		static BNLogLevel GetLogLevelCallback(void* ctxt);

	public:
		virtual ~LogListener() {}

		static void RegisterLogListener(LogListener* listener);
		static void UnregisterLogListener(LogListener* listener);
		static void UpdateLogListeners();

		virtual void LogMessage(BNLogLevel level, const std::string& msg) = 0;
		virtual void CloseLog() {}
		virtual BNLogLevel GetLogLevel() { return WarningLog; }
	};

	class Architecture;
	class BackgroundTask;
	class Platform;
	class Type;
	class DataBuffer;
	class MainThreadAction;
	class MainThreadActionHandler;
	class InteractionHandler;
	class QualifiedName;
	struct FormInputField;

	/*! Logs to the error console with the given BNLogLevel.

		\param level BNLogLevel debug log level
		\param fmt C-style format string.
		\param ... Variable arguments corresponding to the format string.
	 */
	void Log(BNLogLevel level, const char* fmt, ...);

	/*! LogDebug only writes text to the error console if the console is set to log level: DebugLog
		Log level DebugLog is the most verbose logging level.

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

	/*! LogError writes text to the error console and pops up the error console. Additionall,
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

	void LogToStdout(BNLogLevel minimumLevel);
	void LogToStderr(BNLogLevel minimumLevel);
	bool LogToFile(BNLogLevel minimumLevel, const std::string& path, bool append = false);
	void CloseLogs();

	std::string EscapeString(const std::string& s);
	std::string UnescapeString(const std::string& s);

	bool PreprocessSource(const std::string& source, const std::string& fileName,
	                      std::string& output, std::string& errors,
	                      const std::vector<std::string>& includeDirs = std::vector<std::string>());

	void InitCorePlugins();
	void InitUserPlugins();
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

	bool ExecuteWorkerProcess(const std::string& path, const std::vector<std::string>& args, const DataBuffer& input,
	                          std::string& output, std::string& errors, bool stdoutIsText=false, bool stderrIsText=true);

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
	bool DemangleMS(Architecture* arch,
	                const std::string& mangledName,
	                Type** outType,
	                QualifiedName& outVarName);
	bool DemangleGNU3(Architecture* arch,
	                  const std::string& mangledName,
	                  Type** outType,
	                  QualifiedName& outVarName);

	void RegisterMainThread(MainThreadActionHandler* handler);
	Ref<MainThreadAction> ExecuteOnMainThread(const std::function<void()>& action);
	void ExecuteOnMainThreadAndWait(const std::function<void()>& action);

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
	void ShowMarkdownReport(const std::string& title, const std::string& contents,
		const std::string& plainText = "");
	void ShowHTMLReport(const std::string& title, const std::string& contents,
		const std::string& plainText = "");

	bool GetTextLineInput(std::string& result, const std::string& prompt, const std::string& title);
	bool GetIntegerInput(int64_t& result, const std::string& prompt, const std::string& title);
	bool GetAddressInput(uint64_t& result, const std::string& prompt, const std::string& title);
	bool GetChoiceInput(size_t& idx, const std::string& prompt, const std::string& title,
		const std::vector<std::string>& choices);
	bool GetOpenFileNameInput(std::string& result, const std::string& prompt, const std::string& ext = "");
	bool GetSaveFileNameInput(std::string& result, const std::string& prompt, const std::string& ext = "",
		const std::string& defaultName = "");
	bool GetDirectoryNameInput(std::string& result, const std::string& prompt, const std::string& defaultName = "");
	bool GetFormInput(std::vector<FormInputField>& fields, const std::string& title);

	BNMessageBoxButtonResult ShowMessageBox(const std::string& title, const std::string& text,
		BNMessageBoxButtonSet buttons = OKButtonSet, BNMessageBoxIcon icon = InformationIcon);

	std::string GetUniqueIdentifierString();

	class QualifiedName
	{
		std::vector<std::string> m_name;

	public:
		QualifiedName();
		QualifiedName(const std::string& name);
		QualifiedName(const std::vector<std::string>& name);
		QualifiedName(const QualifiedName& name);

		QualifiedName& operator=(const std::string& name);
		QualifiedName& operator=(const std::vector<std::string>& name);
		QualifiedName& operator=(const QualifiedName& name);

		bool operator==(const QualifiedName& other) const;
		bool operator!=(const QualifiedName& other) const;
		bool operator<(const QualifiedName& other) const;

		QualifiedName operator+(const QualifiedName& other) const;

		std::string& operator[](size_t i);
		const std::string& operator[](size_t i) const;
		std::vector<std::string>::iterator begin();
		std::vector<std::string>::iterator end();
		std::vector<std::string>::const_iterator begin() const;
		std::vector<std::string>::const_iterator end() const;
		std::string& front();
		const std::string& front() const;
		std::string& back();
		const std::string& back() const;
		void insert(std::vector<std::string>::iterator loc, const std::string& name);
		void insert(std::vector<std::string>::iterator loc, std::vector<std::string>::iterator b,
			std::vector<std::string>::iterator e);
		void erase(std::vector<std::string>::iterator i);
		void clear();
		void push_back(const std::string& name);
		// Returns count of names
		size_t size() const;
		// Returns size of output string
		size_t StringSize() const;
		std::string GetString() const;

		BNQualifiedName GetAPIObject() const;
		static void FreeAPIObject(BNQualifiedName* name);
		static QualifiedName FromAPIObject(BNQualifiedName* name);
	};

	class DataBuffer
	{
		BNDataBuffer* m_buffer;

	public:
		DataBuffer();
		DataBuffer(size_t len);
		DataBuffer(const void* data, size_t len);
		DataBuffer(const DataBuffer& buf);
		DataBuffer(BNDataBuffer* buf);
		~DataBuffer();

		DataBuffer& operator=(const DataBuffer& buf);

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

		std::string ToEscapedString() const;
		static DataBuffer FromEscapedString(const std::string& src);
		std::string ToBase64() const;
		static DataBuffer FromBase64(const std::string& src);

		bool ZlibCompress(DataBuffer& output) const;
		bool ZlibDecompress(DataBuffer& output) const;
	};

	class TemporaryFile: public CoreRefCountObject<BNTemporaryFile, BNNewTemporaryFileReference, BNFreeTemporaryFile>
	{
	public:
		TemporaryFile();
		TemporaryFile(const DataBuffer& contents);
		TemporaryFile(const std::string& contents);
		TemporaryFile(BNTemporaryFile* file);

		bool IsValid() const { return m_object != nullptr; }
		std::string GetPath() const;
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

	class BinaryView;

	class UndoAction
	{
	private:
		std::string m_typeName;
		BNActionType m_actionType;

		static void FreeCallback(void* ctxt);
		static void UndoCallback(void* ctxt, BNBinaryView* data);
		static void RedoCallback(void* ctxt, BNBinaryView* data);
		static char* SerializeCallback(void* ctxt);

	public:
		UndoAction(const std::string& name, BNActionType action);
		virtual ~UndoAction() {}

		const std::string& GetTypeName() const { return m_typeName; }
		BNActionType GetActionType() const { return m_actionType; }
		BNUndoAction GetCallbacks();

		void Add(BNBinaryView* view);

		virtual void Undo(BinaryView* data) = 0;
		virtual void Redo(BinaryView* data) = 0;
		virtual Json::Value Serialize() = 0;
	};

	class UndoActionType
	{
	protected:
		std::string m_nameForRegister;

		static bool DeserializeCallback(void* ctxt, const char* data, BNUndoAction* result);

	public:
		UndoActionType(const std::string& name);
		virtual ~UndoActionType() {}

		static void Register(UndoActionType* type);

		virtual UndoAction* Deserialize(const Json::Value& data) = 0;
	};

	class FileMetadata: public CoreRefCountObject<BNFileMetadata, BNNewFileReference, BNFreeFileMetadata>
	{
	public:
		FileMetadata();
		FileMetadata(const std::string& filename);
		FileMetadata(BNFileMetadata* file);

		void Close();

		void SetNavigationHandler(NavigationHandler* handler);

		std::string GetFilename() const;
		void SetFilename(const std::string& name);

		bool IsModified() const;
		bool IsAnalysisChanged() const;
		void MarkFileModified();
		void MarkFileSaved();

		bool IsBackedByDatabase() const;
		bool CreateDatabase(const std::string& name, BinaryView* data);
		bool CreateDatabase(const std::string& name, BinaryView* data,
			const std::function<void(size_t progress, size_t total)>& progressCallback);
		Ref<BinaryView> OpenExistingDatabase(const std::string& path);
		Ref<BinaryView> OpenExistingDatabase(const std::string& path,
			const std::function<void(size_t progress, size_t total)>& progressCallback);
		bool SaveAutoSnapshot(BinaryView* data);
		bool SaveAutoSnapshot(BinaryView* data,
			const std::function<void(size_t progress, size_t total)>& progressCallback);

		void BeginUndoActions();
		void CommitUndoActions();

		bool Undo();
		bool Redo();

		std::string GetCurrentView();
		uint64_t GetCurrentOffset();
		bool Navigate(const std::string& view, uint64_t offset);

		BinaryNinja::Ref<BinaryNinja::BinaryView> GetViewOfType(const std::string& name);
	};

	class BinaryView;
	class Function;
	struct DataVariable;

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
		static void StringFoundCallback(void* ctxt, BNBinaryView* data, BNStringType type, uint64_t offset, size_t len);
		static void StringRemovedCallback(void* ctxt, BNBinaryView* data, BNStringType type, uint64_t offset, size_t len);
		static void TypeDefinedCallback(void* ctxt, BNBinaryView* data, BNQualifiedName* name, BNType* type);
		static void TypeUndefinedCallback(void* ctxt, BNBinaryView* data, BNQualifiedName* name, BNType* type);

	public:
		BinaryDataNotification();
		virtual ~BinaryDataNotification() {}

		BNBinaryDataNotification* GetCallbacks() { return &m_callbacks; }

		virtual void OnBinaryDataWritten(BinaryView* view, uint64_t offset, size_t len) { (void)view; (void)offset; (void)len; }
		virtual void OnBinaryDataInserted(BinaryView* view, uint64_t offset, size_t len) { (void)view; (void)offset; (void)len; }
		virtual void OnBinaryDataRemoved(BinaryView* view, uint64_t offset, uint64_t len) { (void)view; (void)offset; (void)len; }
		virtual void OnAnalysisFunctionAdded(BinaryView* view, Function* func) { (void)view; (void)func; }
		virtual void OnAnalysisFunctionRemoved(BinaryView* view, Function* func) { (void)view; (void)func; }
		virtual void OnAnalysisFunctionUpdated(BinaryView* view, Function* func) { (void)view; (void)func; }
		virtual void OnAnalysisFunctionUpdateRequested(BinaryView* view, Function* func) { (void)view; (void)func; }
		virtual void OnDataVariableAdded(BinaryView* view, const DataVariable& var) { (void)view; (void)var; }
		virtual void OnDataVariableRemoved(BinaryView* view, const DataVariable& var) { (void)view; (void)var; }
		virtual void OnDataVariableUpdated(BinaryView* view, const DataVariable& var) { (void)view; (void)var; }
		virtual void OnStringFound(BinaryView* data, BNStringType type, uint64_t offset, size_t len) { (void)data; (void)type; (void)offset; (void)len; }
		virtual void OnStringRemoved(BinaryView* data, BNStringType type, uint64_t offset, size_t len) { (void)data; (void)type; (void)offset; (void)len; }
		virtual void OnTypeDefined(BinaryView* data, const QualifiedName& name, Type* type) { (void)data; (void)name; (void)type; }
		virtual void OnTypeUndefined(BinaryView* data, const QualifiedName& name, Type* type) { (void)data; (void)name; (void)type; }
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

	class CoreFileAccessor: public FileAccessor
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

	class Symbol: public CoreRefCountObject<BNSymbol, BNNewSymbolReference, BNFreeSymbol>
	{
	public:
		Symbol(BNSymbolType type, const std::string& shortName, const std::string& fullName,
		       const std::string& rawName, uint64_t addr);
		Symbol(BNSymbolType type, const std::string& name, uint64_t addr);
		Symbol(BNSymbol* sym);

		BNSymbolType GetType() const;
		std::string GetShortName() const;
		std::string GetFullName() const;
		std::string GetRawName() const;
		uint64_t GetAddress() const;
		bool IsAutoDefined() const;
		void SetAutoDefined(bool val);

		static Ref<Symbol> ImportedFunctionFromImportAddressSymbol(Symbol* sym, uint64_t addr);
	};

	struct ReferenceSource
	{
		Ref<Function> func;
		Ref<Architecture> arch;
		uint64_t addr;
	};

	struct InstructionTextToken
	{
		BNInstructionTextTokenType type;
		std::string text;
		uint64_t value;
		size_t size, operand;
		BNInstructionTextTokenContext context;
		uint8_t confidence;
		uint64_t address;

		InstructionTextToken();
		InstructionTextToken(uint8_t confidence, BNInstructionTextTokenType t, const std::string& txt);
		InstructionTextToken(BNInstructionTextTokenType type, const std::string& text, uint64_t value = 0,
			size_t size = 0, size_t operand = BN_INVALID_OPERAND, uint8_t confidence = BN_FULL_CONFIDENCE);
		InstructionTextToken(BNInstructionTextTokenType type, BNInstructionTextTokenContext context,
			const std::string& text, uint64_t address, uint64_t value = 0, size_t size = 0,
			size_t operand = BN_INVALID_OPERAND, uint8_t confidence = BN_FULL_CONFIDENCE);

		InstructionTextToken WithConfidence(uint8_t conf);
	};

	struct DisassemblyTextLine
	{
		uint64_t addr;
		size_t instrIndex;
		std::vector<InstructionTextToken> tokens;
	};

	struct LinearDisassemblyPosition
	{
		Ref<Function> function;
		Ref<BasicBlock> block;
		uint64_t address;
	};

	struct LinearDisassemblyLine
	{
		BNLinearDisassemblyLineType type;
		Ref<Function> function;
		Ref<BasicBlock> block;
		size_t lineOffset;
		DisassemblyTextLine contents;
	};

	class DisassemblySettings;

	class AnalysisCompletionEvent: public CoreRefCountObject<BNAnalysisCompletionEvent,
		BNNewAnalysisCompletionEventReference, BNFreeAnalysisCompletionEvent>
	{
	protected:
		std::function<void()> m_callback;
		std::recursive_mutex m_mutex;

		static void CompletionCallback(void* ctxt);

	public:
		AnalysisCompletionEvent(BinaryView* view, const std::function<void()>& callback);
		void Cancel();
	};

	struct DataVariable
	{
		DataVariable() { }
		DataVariable(uint64_t a, Type* t, bool d) : address(a), type(t), autoDiscovered(d) { }

		uint64_t address;
		Confidence<Ref<Type>> type;
		bool autoDiscovered;
	};

	struct Segment
	{
		uint64_t start, length;
		uint64_t dataOffset, dataLength;
		uint32_t flags;
		bool autoDefined;
	};

	struct Section
	{
		std::string name, type;
		uint64_t start, length;
		std::string linkedSection, infoSection;
		uint64_t infoData;
		uint64_t align, entrySize;
		BNSectionSemantics semantics;
		bool autoDefined;
	};

	struct QualifiedNameAndType;
	class Metadata;

	class QueryMetadataException: public std::exception
	{
		const std::string m_error;
	public:
		QueryMetadataException(const std::string& error): std::exception(), m_error(error) {}
		virtual const char* what() const NOEXCEPT { return m_error.c_str(); }
	};

	/*! BinaryView is the base class for creating views on binary data (e.g. ELF, PE, Mach-O).
	    BinaryView should be subclassed to create a new BinaryView
	*/
	class BinaryView: public CoreRefCountObject<BNBinaryView, BNNewViewReference, BNFreeBinaryView>
	{
	protected:
		Ref<FileMetadata> m_file; //!< The underlying file

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
		virtual size_t PerformRead(void* dest, uint64_t offset, size_t len) { (void)dest; (void)offset; (void)len; return 0; }
		virtual size_t PerformWrite(uint64_t offset, const void* data, size_t len) { (void)offset; (void)data; (void)len; return 0; }
		virtual size_t PerformInsert(uint64_t offset, const void* data, size_t len) { (void)offset; (void)data; (void)len; return 0; }
		virtual size_t PerformRemove(uint64_t offset, uint64_t len) { (void)offset; (void)len; return 0; }

		virtual BNModificationStatus PerformGetModification(uint64_t offset) { (void)offset; return Original; }
		virtual bool PerformIsValidOffset(uint64_t offset);
		virtual bool PerformIsOffsetReadable(uint64_t offset);
		virtual bool PerformIsOffsetWritable(uint64_t offset);
		virtual bool PerformIsOffsetExecutable(uint64_t offset);
		virtual bool PerformIsOffsetBackedByFile(uint64_t offset);
		virtual uint64_t PerformGetNextValidOffset(uint64_t offset);
		virtual uint64_t PerformGetStart() const { return 0; }
		virtual uint64_t PerformGetLength() const { return 0; }
		virtual uint64_t PerformGetEntryPoint() const { return 0; }
		virtual bool PerformIsExecutable() const { return false; }
		virtual BNEndianness PerformGetDefaultEndianness() const;
		virtual bool PerformIsRelocatable() const;
		virtual size_t PerformGetAddressSize() const;

		virtual bool PerformSave(FileAccessor* file);

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

		FileMetadata* GetFile() const { return m_file; }
		Ref<BinaryView> GetParentView() const;
		std::string GetTypeName() const;

		bool IsModified() const;
		bool IsAnalysisChanged() const;
		bool IsBackedByDatabase() const;
		bool CreateDatabase(const std::string& path);
		bool CreateDatabase(const std::string& path,
			const std::function<void(size_t progress, size_t total)>& progressCallback);
		bool SaveAutoSnapshot();
		bool SaveAutoSnapshot(const std::function<void(size_t progress, size_t total)>& progressCallback);

		void BeginUndoActions();
		void AddUndoAction(UndoAction* action);
		void CommitUndoActions();

		bool Undo();
		bool Redo();

		std::string GetCurrentView();
		uint64_t GetCurrentOffset();
		bool Navigate(const std::string& view, uint64_t offset);

		size_t Read(void* dest, uint64_t offset, size_t len);
		DataBuffer ReadBuffer(uint64_t offset, size_t len);

		size_t Write(uint64_t offset, const void* data, size_t len);
		size_t WriteBuffer(uint64_t offset, const DataBuffer& data);

		size_t Insert(uint64_t offset, const void* data, size_t len);
		size_t InsertBuffer(uint64_t offset, const DataBuffer& data);

		size_t Remove(uint64_t offset, uint64_t len);

		BNModificationStatus GetModification(uint64_t offset);
		std::vector<BNModificationStatus> GetModification(uint64_t offset, size_t len);

		bool IsValidOffset(uint64_t offset) const;
		bool IsOffsetReadable(uint64_t offset) const;
		bool IsOffsetWritable(uint64_t offset) const;
		bool IsOffsetExecutable(uint64_t offset) const;
		bool IsOffsetBackedByFile(uint64_t offset) const;
		bool IsOffsetCodeSemantics(uint64_t offset) const;
		bool IsOffsetWritableSemantics(uint64_t offset) const;
		uint64_t GetNextValidOffset(uint64_t offset) const;

		uint64_t GetStart() const;
		uint64_t GetEnd() const;
		uint64_t GetLength() const;
		uint64_t GetEntryPoint() const;

		Ref<Architecture> GetDefaultArchitecture() const;
		void SetDefaultArchitecture(Architecture* arch);
		Ref<Platform> GetDefaultPlatform() const;
		void SetDefaultPlatform(Platform* platform);

		BNEndianness GetDefaultEndianness() const;
		bool IsRelocatable() const;
		size_t GetAddressSize() const;

		bool IsExecutable() const;

		bool Save(FileAccessor* file);
		bool Save(const std::string& path);

		void RegisterNotification(BinaryDataNotification* notify);
		void UnregisterNotification(BinaryDataNotification* notify);

		void AddAnalysisOption(const std::string& name);
		void AddFunctionForAnalysis(Platform* platform, uint64_t addr);
		void AddEntryPointForAnalysis(Platform* platform, uint64_t start);
		void RemoveAnalysisFunction(Function* func);
		void CreateUserFunction(Platform* platform, uint64_t start);
		void RemoveUserFunction(Function* func);
		void UpdateAnalysisAndWait();
		void UpdateAnalysis();
		void AbortAnalysis();

		void DefineDataVariable(uint64_t addr, const Confidence<Ref<Type>>& type);
		void DefineUserDataVariable(uint64_t addr, const Confidence<Ref<Type>>& type);
		void UndefineDataVariable(uint64_t addr);
		void UndefineUserDataVariable(uint64_t addr);

		std::map<uint64_t, DataVariable> GetDataVariables();
		bool GetDataVariableAtAddress(uint64_t addr, DataVariable& var);

		std::vector<Ref<Function>> GetAnalysisFunctionList();
		bool HasFunctions() const;
		Ref<Function> GetAnalysisFunction(Platform* platform, uint64_t addr);
		Ref<Function> GetRecentAnalysisFunctionForAddress(uint64_t addr);
		std::vector<Ref<Function>> GetAnalysisFunctionsForAddress(uint64_t addr);
		Ref<Function> GetAnalysisEntryPoint();

		Ref<BasicBlock> GetRecentBasicBlockForAddress(uint64_t addr);
		std::vector<Ref<BasicBlock>> GetBasicBlocksForAddress(uint64_t addr);
		std::vector<Ref<BasicBlock>> GetBasicBlocksStartingAtAddress(uint64_t addr);

		std::vector<ReferenceSource> GetCodeReferences(uint64_t addr);
		std::vector<ReferenceSource> GetCodeReferences(uint64_t addr, uint64_t len);

		Ref<Symbol> GetSymbolByAddress(uint64_t addr);
		Ref<Symbol> GetSymbolByRawName(const std::string& name);
		std::vector<Ref<Symbol>> GetSymbolsByName(const std::string& name);
		std::vector<Ref<Symbol>> GetSymbols();
		std::vector<Ref<Symbol>> GetSymbols(uint64_t start, uint64_t len);
		std::vector<Ref<Symbol>> GetSymbolsOfType(BNSymbolType type);
		std::vector<Ref<Symbol>> GetSymbolsOfType(BNSymbolType type, uint64_t start, uint64_t len);

		void DefineAutoSymbol(Ref<Symbol> sym);
		void DefineAutoSymbolAndVariableOrFunction(Ref<Platform> platform, Ref<Symbol> sym, Ref<Type> type);
		void UndefineAutoSymbol(Ref<Symbol> sym);

		void DefineUserSymbol(Ref<Symbol> sym);
		void UndefineUserSymbol(Ref<Symbol> sym);

		void DefineImportedFunction(Ref<Symbol> importAddressSym, Ref<Function> func);

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

		std::vector<BNStringReference> GetStrings();
		std::vector<BNStringReference> GetStrings(uint64_t start, uint64_t len);

		Ref<AnalysisCompletionEvent> AddAnalysisCompletionEvent(const std::function<void()>& callback);

		BNAnalysisProgress GetAnalysisProgress();
		Ref<BackgroundTask> GetBackgroundAnalysisTask();

		uint64_t GetNextFunctionStartAfterAddress(uint64_t addr);
		uint64_t GetNextBasicBlockStartAfterAddress(uint64_t addr);
		uint64_t GetNextDataAfterAddress(uint64_t addr);
		uint64_t GetNextDataVariableAfterAddress(uint64_t addr);
		uint64_t GetPreviousFunctionStartBeforeAddress(uint64_t addr);
		uint64_t GetPreviousBasicBlockStartBeforeAddress(uint64_t addr);
		uint64_t GetPreviousBasicBlockEndBeforeAddress(uint64_t addr);
		uint64_t GetPreviousDataBeforeAddress(uint64_t addr);
		uint64_t GetPreviousDataVariableBeforeAddress(uint64_t addr);

		LinearDisassemblyPosition GetLinearDisassemblyPositionForAddress(uint64_t addr, DisassemblySettings* settings);
		std::vector<LinearDisassemblyLine> GetPreviousLinearDisassemblyLines(LinearDisassemblyPosition& pos,
			DisassemblySettings* settings);
		std::vector<LinearDisassemblyLine> GetNextLinearDisassemblyLines(LinearDisassemblyPosition& pos,
			DisassemblySettings* settings);

		bool ParseTypeString(const std::string& text, QualifiedNameAndType& result, std::string& errors);

		std::map<QualifiedName, Ref<Type>> GetTypes();
		Ref<Type> GetTypeByName(const QualifiedName& name);
		Ref<Type> GetTypeById(const std::string& id);
		std::string GetTypeId(const QualifiedName& name);
		QualifiedName GetTypeNameById(const std::string& id);
		bool IsTypeAutoDefined(const QualifiedName& name);
		QualifiedName DefineType(const std::string& id, const QualifiedName& defaultName, Ref<Type> type);
		void DefineUserType(const QualifiedName& name, Ref<Type> type);
		void UndefineType(const std::string& id);
		void UndefineUserType(const QualifiedName& name);
		void RenameType(const QualifiedName& oldName, const QualifiedName& newName);

		void RegisterPlatformTypes(Platform* platform);

		bool FindNextData(uint64_t start, const DataBuffer& data, uint64_t& result, BNFindFlag flags = NoFindFlags);

		void Reanalyze();

		void ShowPlainTextReport(const std::string& title, const std::string& contents);
		void ShowMarkdownReport(const std::string& title, const std::string& contents, const std::string& plainText);
		void ShowHTMLReport(const std::string& title, const std::string& contents, const std::string& plainText);
		bool GetAddressInput(uint64_t& result, const std::string& prompt, const std::string& title);
		bool GetAddressInput(uint64_t& result, const std::string& prompt, const std::string& title,
			uint64_t currentAddress);

		void AddAutoSegment(uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags);
		void RemoveAutoSegment(uint64_t start, uint64_t length);
		void AddUserSegment(uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags);
		void RemoveUserSegment(uint64_t start, uint64_t length);
		std::vector<Segment> GetSegments();
		bool GetSegmentAt(uint64_t addr, Segment& result);
		bool GetAddressForDataOffset(uint64_t offset, uint64_t& addr);

		void AddAutoSection(const std::string& name, uint64_t start, uint64_t length,
			BNSectionSemantics semantics = DefaultSectionSemantics, const std::string& type = "",
			uint64_t align = 1, uint64_t entrySize = 0, const std::string& linkedSection = "",
			const std::string& infoSection = "", uint64_t infoData = 0);
		void RemoveAutoSection(const std::string& name);
		void AddUserSection(const std::string& name, uint64_t start, uint64_t length,
			BNSectionSemantics semantics = DefaultSectionSemantics, const std::string& type = "",
			uint64_t align = 1, uint64_t entrySize = 0, const std::string& linkedSection = "",
			const std::string& infoSection = "", uint64_t infoData = 0);
		void RemoveUserSection(const std::string& name);
		std::vector<Section> GetSections();
		std::vector<Section> GetSectionsAt(uint64_t addr);
		bool GetSectionByName(const std::string& name, Section& result);

		std::vector<std::string> GetUniqueSectionNames(const std::vector<std::string>& names);

		std::vector<BNAddressRange> GetAllocatedRanges();

		void StoreMetadata(const std::string& key, Ref<Metadata> value);
		Ref<Metadata> QueryMetadata(const std::string& key);
		void RemoveMetadata(const std::string& key);
		std::string GetStringMetadata(const std::string& key);
		std::vector<uint8_t> GetRawMetadata(const std::string& key);
		uint64_t GetUIntMetadata(const std::string& key);

		uint64_t GetMaxFunctionSizeForAnalysis();
		void SetMaxFunctionSizeForAnalysis(uint64_t size);
	};

	class BinaryData: public BinaryView
	{
	public:
		BinaryData(FileMetadata* file);
		BinaryData(FileMetadata* file, const DataBuffer& data);
		BinaryData(FileMetadata* file, const void* data, size_t len);
		BinaryData(FileMetadata* file, const std::string& path);
		BinaryData(FileMetadata* file, FileAccessor* accessor);
	};

	class Platform;

	class BinaryViewType: public StaticCoreRefCountObject<BNBinaryViewType>
	{
	protected:
		std::string m_nameForRegister, m_longNameForRegister;

		static BNBinaryView* CreateCallback(void* ctxt, BNBinaryView* data);
		static bool IsValidCallback(void* ctxt, BNBinaryView* data);

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

		std::string GetName();
		std::string GetLongName();

		virtual BinaryView* Create(BinaryView* data) = 0;
		virtual bool IsTypeValidForData(BinaryView* data) = 0;
	};

	class CoreBinaryViewType: public BinaryViewType
	{
	public:
		CoreBinaryViewType(BNBinaryViewType* type);
		virtual BinaryView* Create(BinaryView* data) override;
		virtual bool IsTypeValidForData(BinaryView* data) override;
	};

	class ReadException: public std::exception
	{
	public:
		ReadException(): std::exception() {}
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
		template <typename T> T Read();
		template <typename T> std::vector<T> ReadVector(size_t count);
		std::string ReadString(size_t len);
		std::string ReadCString(size_t maxLength=-1);

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

	class WriteException: public std::exception
	{
	public:
		WriteException(): std::exception() {}
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
		size_t fixedLength; // Variable length if zero
	};

	class Transform: public StaticCoreRefCountObject<BNTransform>
	{
	protected:
		BNTransformType m_typeForRegister;
		std::string m_nameForRegister, m_longNameForRegister, m_groupForRegister;

		Transform(BNTransform* xform);

		static BNTransformParameterInfo* GetParametersCallback(void* ctxt, size_t* count);
		static void FreeParametersCallback(BNTransformParameterInfo* params, size_t count);
		static bool DecodeCallback(void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);
		static bool EncodeCallback(void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);

		static std::vector<TransformParameter> EncryptionKeyParameters(size_t fixedKeyLength = 0);
		static std::vector<TransformParameter> EncryptionKeyAndIVParameters(size_t fixedKeyLength = 0, size_t fixedIVLength = 0);

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

		virtual bool Decode(const DataBuffer& input, DataBuffer& output, const std::map<std::string, DataBuffer>& params =
		                    std::map<std::string, DataBuffer>());
		virtual bool Encode(const DataBuffer& input, DataBuffer& output, const std::map<std::string, DataBuffer>& params =
		                    std::map<std::string, DataBuffer>());
	};

	class CoreTransform: public Transform
	{
	public:
		CoreTransform(BNTransform* xform);
		virtual std::vector<TransformParameter> GetParameters() const override;

		virtual bool Decode(const DataBuffer& input, DataBuffer& output, const std::map<std::string, DataBuffer>& params =
		                    std::map<std::string, DataBuffer>()) override;
		virtual bool Encode(const DataBuffer& input, DataBuffer& output, const std::map<std::string, DataBuffer>& params =
		                    std::map<std::string, DataBuffer>()) override;
	};

	struct InstructionInfo: public BNInstructionInfo
	{
		InstructionInfo();
		void AddBranch(BNBranchType type, uint64_t target = 0, Architecture* arch = nullptr, bool hasDelaySlot = false);
	};

	struct NameAndType
	{
		std::string name;
		Confidence<Ref<Type>> type;

		NameAndType() {}
		NameAndType(const Confidence<Ref<Type>>& t): type(t) {}
		NameAndType(const std::string& n, const Confidence<Ref<Type>>& t): name(n), type(t) {}
	};

	class LowLevelILFunction;
	class MediumLevelILFunction;
	class FunctionRecognizer;
	class CallingConvention;

	typedef size_t ExprId;

	/*!
		The Architecture class is the base class for all CPU architectures. This provides disassembly, assembly,
		patching, and IL translation lifting for a given architecture.
	*/
	class Architecture: public StaticCoreRefCountObject<BNArchitecture>
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
		static bool GetInstructionInfoCallback(void* ctxt, const uint8_t* data, uint64_t addr,
		                                       size_t maxLen, BNInstructionInfo* result);
		static bool GetInstructionTextCallback(void* ctxt, const uint8_t* data, uint64_t addr,
		                                       size_t* len, BNInstructionTextToken** result, size_t* count);
		static void FreeInstructionTextCallback(BNInstructionTextToken* tokens, size_t count);
		static bool GetInstructionLowLevelILCallback(void* ctxt, const uint8_t* data, uint64_t addr,
		                                             size_t* len, BNLowLevelILFunction* il);
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
		static uint32_t* GetFlagsRequiredForFlagConditionCallback(void* ctxt, BNLowLevelILFlagCondition cond,
			uint32_t semClass, size_t* count);
		static uint32_t* GetFlagsRequiredForSemanticFlagGroupCallback(void* ctxt, uint32_t semGroup, size_t* count);
		static BNFlagConditionForSemanticClass* GetFlagConditionsForSemanticFlagGroupCallback(void* ctxt,
			uint32_t semGroup, size_t* count);
		static void FreeFlagConditionsForSemanticFlagGroupCallback(void* ctxt, BNFlagConditionForSemanticClass* conditions);
		static uint32_t* GetFlagsWrittenByFlagWriteTypeCallback(void* ctxt, uint32_t writeType, size_t* count);
		static uint32_t GetSemanticClassForFlagWriteTypeCallback(void* ctxt, uint32_t writeType);
		static size_t GetFlagWriteLowLevelILCallback(void* ctxt, BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
			uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, BNLowLevelILFunction* il);
		static size_t GetFlagConditionLowLevelILCallback(void* ctxt, BNLowLevelILFlagCondition cond,
			uint32_t semClass, BNLowLevelILFunction* il);
		static size_t GetSemanticFlagGroupLowLevelILCallback(void* ctxt, uint32_t semGroup, BNLowLevelILFunction* il);
		static void FreeRegisterListCallback(void* ctxt, uint32_t* regs);
		static void GetRegisterInfoCallback(void* ctxt, uint32_t reg, BNRegisterInfo* result);
		static uint32_t GetStackPointerRegisterCallback(void* ctxt);
		static uint32_t GetLinkRegisterCallback(void* ctxt);
		static uint32_t* GetGlobalRegistersCallback(void* ctxt, size_t* count);

		static char* GetRegisterStackNameCallback(void* ctxt, uint32_t regStack);
		static uint32_t* GetAllRegisterStacksCallback(void* ctxt, size_t* count);
		static void GetRegisterStackInfoCallback(void* ctxt, uint32_t regStack, BNRegisterStackInfo* result);

		static char* GetIntrinsicNameCallback(void* ctxt, uint32_t intrinsic);
		static uint32_t* GetAllIntrinsicsCallback(void* ctxt, size_t* count);
		static BNNameAndType* GetIntrinsicInputsCallback(void* ctxt, uint32_t intrinsic, size_t* count);
		static void FreeNameAndTypeListCallback(void* ctxt, BNNameAndType* nt, size_t count);
		static BNTypeWithConfidence* GetIntrinsicOutputsCallback(void* ctxt, uint32_t intrinsic, size_t* count);
		static void FreeTypeListCallback(void* ctxt, BNTypeWithConfidence* types, size_t count);

		static bool AssembleCallback(void* ctxt, const char* code, uint64_t addr, BNDataBuffer* result, char** errors);
		static bool IsNeverBranchPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		static bool IsAlwaysBranchPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		static bool IsInvertBranchPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		static bool IsSkipAndReturnZeroPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		static bool IsSkipAndReturnValuePatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);

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
		virtual bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len,
		                                std::vector<InstructionTextToken>& result) = 0;

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
		virtual std::vector<uint32_t> GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond,
			uint32_t semClass = 0);
		virtual std::vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup);
		virtual std::map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(uint32_t semGroup);
		virtual std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType);
		virtual uint32_t GetSemanticClassForFlagWriteType(uint32_t writeType);
		virtual ExprId GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
			uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il);
		ExprId GetDefaultFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, BNFlagRole role,
			BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il);
		virtual ExprId GetFlagConditionLowLevelIL(BNLowLevelILFlagCondition cond, uint32_t semClass, LowLevelILFunction& il);
		ExprId GetDefaultFlagConditionLowLevelIL(BNLowLevelILFlagCondition cond, uint32_t semClass, LowLevelILFunction& il);
		virtual ExprId GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il);
		virtual BNRegisterInfo GetRegisterInfo(uint32_t reg);
		virtual uint32_t GetStackPointerRegister();
		virtual uint32_t GetLinkRegister();
		virtual std::vector<uint32_t> GetGlobalRegisters();
		bool IsGlobalRegister(uint32_t reg);
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

		bool IsBinaryViewTypeConstantDefined(const std::string& type, const std::string& name);
		uint64_t GetBinaryViewTypeConstant(const std::string& type, const std::string& name,
		                                   uint64_t defaultValue = 0);
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

	class CoreArchitecture: public Architecture
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
		virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override;
		virtual bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len,
		                                std::vector<InstructionTextToken>& result) override;
		virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override;
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
		virtual std::vector<uint32_t> GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond,
			uint32_t semClass = 0) override;
		virtual std::vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup) override;
		virtual std::map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(uint32_t semGroup) override;
		virtual std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType) override;
		virtual uint32_t GetSemanticClassForFlagWriteType(uint32_t writeType) override;
		virtual ExprId GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
			uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il) override;
		virtual ExprId GetFlagConditionLowLevelIL(BNLowLevelILFlagCondition cond,
			uint32_t semClass, LowLevelILFunction& il) override;
		virtual ExprId GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il) override;
		virtual BNRegisterInfo GetRegisterInfo(uint32_t reg) override;
		virtual uint32_t GetStackPointerRegister() override;
		virtual uint32_t GetLinkRegister() override;
		virtual std::vector<uint32_t> GetGlobalRegisters() override;

		virtual std::string GetRegisterStackName(uint32_t regStack) override;
		virtual std::vector<uint32_t> GetAllRegisterStacks() override;
		virtual BNRegisterStackInfo GetRegisterStackInfo(uint32_t regStack) override;

		virtual std::string GetIntrinsicName(uint32_t intrinsic) override;
		virtual std::vector<uint32_t> GetAllIntrinsics() override;
		virtual std::vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override;
		virtual std::vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic) override;

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

	class ArchitectureExtension: public Architecture
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
		virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override;
		virtual bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len,
		                                std::vector<InstructionTextToken>& result) override;
		virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override;
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
		virtual std::vector<uint32_t> GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond,
			uint32_t semClass = 0) override;
		virtual std::vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup) override;
		virtual std::map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(uint32_t semGroup) override;
		virtual std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType) override;
		virtual uint32_t GetSemanticClassForFlagWriteType(uint32_t writeType) override;
		virtual ExprId GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
			uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il) override;
		virtual ExprId GetFlagConditionLowLevelIL(BNLowLevelILFlagCondition cond,
			uint32_t semClass, LowLevelILFunction& il) override;
		virtual ExprId GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il) override;
		virtual BNRegisterInfo GetRegisterInfo(uint32_t reg) override;
		virtual uint32_t GetStackPointerRegister() override;
		virtual uint32_t GetLinkRegister() override;
		virtual std::vector<uint32_t> GetGlobalRegisters() override;

		virtual std::string GetRegisterStackName(uint32_t regStack) override;
		virtual std::vector<uint32_t> GetAllRegisterStacks() override;
		virtual BNRegisterStackInfo GetRegisterStackInfo(uint32_t regStack) override;

		virtual std::string GetIntrinsicName(uint32_t intrinsic) override;
		virtual std::vector<uint32_t> GetAllIntrinsics() override;
		virtual std::vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override;
		virtual std::vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic) override;

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

	class ArchitectureHook: public CoreArchitecture
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

	struct Variable: public BNVariable
	{
		Variable();
		Variable(BNVariableSourceType type, uint32_t index, uint64_t storage);
		Variable(BNVariableSourceType type, uint64_t storage);
		Variable(const BNVariable& var);

		Variable& operator=(const Variable& var);

		bool operator==(const Variable& var) const;
		bool operator!=(const Variable& var) const;
		bool operator<(const Variable& var) const;

		uint64_t ToIdentifier() const;
		static Variable FromIdentifier(uint64_t id);
	};

	struct FunctionParameter
	{
		std::string name;
		Confidence<Ref<Type>> type;
		bool defaultLocation;
		Variable location;
	};

	struct QualifiedNameAndType
	{
		QualifiedName name;
		Ref<Type> type;
	};

	class Type: public CoreRefCountObject<BNType, BNNewTypeReference, BNFreeType>
	{
	public:
		Type(BNType* type);

		BNTypeClass GetClass() const;
		uint64_t GetWidth() const;
		size_t GetAlignment() const;
		QualifiedName GetTypeName() const;
		Confidence<bool> IsSigned() const;
		Confidence<bool> IsConst() const;
		Confidence<bool> IsVolatile() const;
		bool IsFloat() const;
		Confidence<Ref<Type>> GetChildType() const;
		Confidence<Ref<CallingConvention>> GetCallingConvention() const;
		std::vector<FunctionParameter> GetParameters() const;
		Confidence<bool> HasVariableArguments() const;
		Confidence<bool> CanReturn() const;
		Ref<Structure> GetStructure() const;
		Ref<Enumeration> GetEnumeration() const;
		Ref<NamedTypeReference> GetNamedTypeReference() const;
		Confidence<BNMemberScope> GetScope() const;
		void SetScope(const Confidence<BNMemberScope>& scope);
		Confidence<BNMemberAccess> GetAccess() const;
		void SetAccess(const Confidence<BNMemberAccess>& access);
		void SetConst(const Confidence<bool>& cnst);
		void SetVolatile(const Confidence<bool>& vltl);
		void SetTypeName(const QualifiedName& name);
		Confidence<size_t> GetStackAdjustment() const;

		uint64_t GetElementCount() const;
		uint64_t GetOffset() const;

		void SetFunctionCanReturn(const Confidence<bool>& canReturn);

		std::string GetString(Platform* platform = nullptr) const;
		std::string GetTypeAndName(const QualifiedName& name) const;
		std::string GetStringBeforeName(Platform* platform = nullptr) const;
		std::string GetStringAfterName(Platform* platform = nullptr) const;

		std::vector<InstructionTextToken> GetTokens(Platform* platform = nullptr,
			uint8_t baseConfidence = BN_FULL_CONFIDENCE) const;
		std::vector<InstructionTextToken> GetTokensBeforeName(Platform* platform = nullptr,
			uint8_t baseConfidence = BN_FULL_CONFIDENCE) const;
		std::vector<InstructionTextToken> GetTokensAfterName(Platform* platform = nullptr,
			uint8_t baseConfidence = BN_FULL_CONFIDENCE) const;

		Ref<Type> Duplicate() const;

		static Ref<Type> VoidType();
		static Ref<Type> BoolType();
		static Ref<Type> IntegerType(size_t width, const Confidence<bool>& sign, const std::string& altName = "");
		static Ref<Type> FloatType(size_t width, const std::string& typeName = "");
		static Ref<Type> StructureType(Structure* strct);
		static Ref<Type> NamedType(NamedTypeReference* ref, size_t width = 0, size_t align = 1);
		static Ref<Type> NamedType(const QualifiedName& name, Type* type);
		static Ref<Type> NamedType(const std::string& id, const QualifiedName& name, Type* type);
		static Ref<Type> NamedType(BinaryView* view, const QualifiedName& name);
		static Ref<Type> EnumerationType(Architecture* arch, Enumeration* enm, size_t width = 0, bool issigned = false);
		static Ref<Type> PointerType(Architecture* arch, const Confidence<Ref<Type>>& type,
			const Confidence<bool>& cnst = Confidence<bool>(false, 0),
			const Confidence<bool>& vltl = Confidence<bool>(false, 0), BNReferenceType refType = PointerReferenceType);
		static Ref<Type> PointerType(size_t width, const Confidence<Ref<Type>>& type,
			const Confidence<bool>& cnst = Confidence<bool>(false, 0),
			const Confidence<bool>& vltl = Confidence<bool>(false, 0), BNReferenceType refType = PointerReferenceType);
		static Ref<Type> ArrayType(const Confidence<Ref<Type>>& type, uint64_t elem);
		static Ref<Type> FunctionType(const Confidence<Ref<Type>>& returnValue,
			const Confidence<Ref<CallingConvention>>& callingConvention,
			const std::vector<FunctionParameter>& params, const Confidence<bool>& varArg = Confidence<bool>(false, 0),
			const Confidence<size_t>& stackAdjust = Confidence<size_t>(0, 0));

 		static std::string GenerateAutoTypeId(const std::string& source, const QualifiedName& name);
		static std::string GenerateAutoDemangledTypeId(const QualifiedName& name);
		static std::string GetAutoDemangledTypeIdSource();
		static std::string GenerateAutoDebugTypeId(const QualifiedName& name);
		static std::string GetAutoDebugTypeIdSource();

		Confidence<Ref<Type>> WithConfidence(uint8_t conf);
	};

	class NamedTypeReference: public CoreRefCountObject<BNNamedTypeReference, BNNewNamedTypeReference,
		BNFreeNamedTypeReference>
	{
	public:
		NamedTypeReference(BNNamedTypeReference* nt);
		NamedTypeReference(BNNamedTypeReferenceClass cls = UnknownNamedTypeClass, const std::string& id = "",
			const QualifiedName& name = QualifiedName());
		BNNamedTypeReferenceClass GetTypeClass() const;
		void SetTypeClass(BNNamedTypeReferenceClass cls);
		std::string GetTypeId() const;
		void SetTypeId(const std::string& id);
		QualifiedName GetName() const;
		void SetName(const QualifiedName& name);

		static Ref<NamedTypeReference> GenerateAutoTypeReference(BNNamedTypeReferenceClass cls,
			const std::string& source, const QualifiedName& name);
		static Ref<NamedTypeReference> GenerateAutoDemangledTypeReference(BNNamedTypeReferenceClass cls,
			const QualifiedName& name);
		static Ref<NamedTypeReference> GenerateAutoDebugTypeReference(BNNamedTypeReferenceClass cls,
			const QualifiedName& name);
	};

	struct StructureMember
	{
		Ref<Type> type;
		std::string name;
		uint64_t offset;
	};

	class Structure: public CoreRefCountObject<BNStructure, BNNewStructureReference, BNFreeStructure>
	{
	public:
		Structure();
		Structure(BNStructure* s);
		Structure(BNStructureType type, bool packed = false);

		std::vector<StructureMember> GetMembers() const;
		uint64_t GetWidth() const;
		void SetWidth(size_t width);
		size_t GetAlignment() const;
		void SetAlignment(size_t align);
		bool IsPacked() const;
		void SetPacked(bool packed);
		bool IsUnion() const;
		void SetStructureType(BNStructureType type);
		BNStructureType GetStructureType() const;
		void AddMember(const Confidence<Ref<Type>>& type, const std::string& name);
		void AddMemberAtOffset(const Confidence<Ref<Type>>& type, const std::string& name, uint64_t offset);
		void RemoveMember(size_t idx);
		void ReplaceMember(size_t idx, const Confidence<Ref<Type>>& type, const std::string& name);
	};

	struct EnumerationMember
	{
		std::string name;
		uint64_t value;
		bool isDefault;
	};

	class Enumeration: public CoreRefCountObject<BNEnumeration, BNNewEnumerationReference, BNFreeEnumeration>
	{
	public:
		Enumeration();
		Enumeration(BNEnumeration* e);

		std::vector<EnumerationMember> GetMembers() const;

		void AddMember(const std::string& name);
		void AddMemberWithValue(const std::string& name, uint64_t value);
		void RemoveMember(size_t idx);
		void ReplaceMember(size_t idx, const std::string& name, uint64_t value);
	};

	class DisassemblySettings: public CoreRefCountObject<BNDisassemblySettings,
		BNNewDisassemblySettingsReference, BNFreeDisassemblySettings>
	{
	public:
		DisassemblySettings();
		DisassemblySettings(BNDisassemblySettings* settings);

		bool IsOptionSet(BNDisassemblyOption option) const;
		void SetOption(BNDisassemblyOption option, bool state = true);

		size_t GetWidth() const;
		void SetWidth(size_t width);
		size_t GetMaximumSymbolWidth() const;
		void SetMaximumSymbolWidth(size_t width);
	};

	class Function;

	struct BasicBlockEdge
	{
		BNBranchType type;
		Ref<BasicBlock> target;
		bool backEdge;
	};

	class BasicBlock: public CoreRefCountObject<BNBasicBlock, BNNewBasicBlockReference, BNFreeBasicBlock>
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

		std::set<Ref<BasicBlock>> GetDominators() const;
		std::set<Ref<BasicBlock>> GetStrictDominators() const;
		Ref<BasicBlock> GetImmediateDominator() const;
		std::set<Ref<BasicBlock>> GetDominatorTreeChildren() const;
		std::set<Ref<BasicBlock>> GetDominanceFrontier() const;
		static std::set<Ref<BasicBlock>> GetIteratedDominanceFrontier(const std::set<Ref<BasicBlock>>& blocks);

		void MarkRecentUse();

		std::vector<std::vector<InstructionTextToken>> GetAnnotations();

		std::vector<DisassemblyTextLine> GetDisassemblyText(DisassemblySettings* settings);

		BNHighlightColor GetBasicBlockHighlight();
		void SetAutoBasicBlockHighlight(BNHighlightColor color);
		void SetAutoBasicBlockHighlight(BNHighlightStandardColor color, uint8_t alpha = 255);
		void SetAutoBasicBlockHighlight(BNHighlightStandardColor color, BNHighlightStandardColor mixColor,
			uint8_t mix, uint8_t alpha = 255);
		void SetAutoBasicBlockHighlight(uint8_t r, uint8_t g, uint8_t b, uint8_t alpha = 255);
		void SetUserBasicBlockHighlight(BNHighlightColor color);
		void SetUserBasicBlockHighlight(BNHighlightStandardColor color, uint8_t alpha = 255);
		void SetUserBasicBlockHighlight(BNHighlightStandardColor color, BNHighlightStandardColor mixColor,
			uint8_t mix, uint8_t alpha = 255);
		void SetUserBasicBlockHighlight(uint8_t r, uint8_t g, uint8_t b, uint8_t alpha = 255);

		static bool IsBackEdge(BasicBlock* source, BasicBlock* target);

		bool IsILBlock() const;
		bool IsLowLevelILBlock() const;
		bool IsMediumLevelILBlock() const;
		Ref<LowLevelILFunction> GetLowLevelILFunction() const;
		Ref<MediumLevelILFunction> GetMediumLevelILFunction() const;
	};

	struct VariableNameAndType
	{
		Variable var;
		Confidence<Ref<Type>> type;
		std::string name;
		bool autoDefined;
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

		ArchAndAddr(): arch(nullptr), address(0) {}
		ArchAndAddr(Architecture* a, uint64_t addr): arch(a), address(addr) {}
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

		RegisterValue();
		static RegisterValue FromAPIObject(const BNRegisterValue& value);
		BNRegisterValue ToAPIObject();
	};

	struct PossibleValueSet
	{
		BNRegisterValueType state;
		int64_t value;
		std::vector<BNValueRange> ranges;
		std::set<int64_t> valueSet;
		std::vector<LookupTableEntry> table;

		static PossibleValueSet FromAPIObject(BNPossibleValueSet& value);
	};

	class FunctionGraph;
	class MediumLevelILFunction;

	class Function: public CoreRefCountObject<BNFunction, BNNewFunctionReference, BNFreeFunction>
	{
		int m_advancedAnalysisRequests;

	public:
		Function(BNFunction* func);
		virtual ~Function();

		Ref<Architecture> GetArchitecture() const;
		Ref<Platform> GetPlatform() const;
		uint64_t GetStart() const;
		Ref<Symbol> GetSymbol() const;
		bool WasAutomaticallyDiscovered() const;
		Confidence<bool> CanReturn() const;
		bool HasExplicitlyDefinedType() const;
		bool NeedsUpdate() const;

		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;
		Ref<BasicBlock> GetBasicBlockAtAddress(Architecture* arch, uint64_t addr) const;
		void MarkRecentUse();

		std::string GetComment() const;
		std::string GetCommentForAddress(uint64_t addr) const;
		std::vector<uint64_t> GetCommentedAddresses() const;
		void SetComment(const std::string& comment);
		void SetCommentForAddress(uint64_t addr, const std::string& comment);

		Ref<LowLevelILFunction> GetLowLevelIL() const;
		size_t GetLowLevelILForInstruction(Architecture* arch, uint64_t addr);
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
		std::vector<BNConstantReference> GetConstantsReferencedByInstruction(Architecture* arch, uint64_t addr);

		Ref<LowLevelILFunction> GetLiftedIL() const;
		size_t GetLiftedILForInstruction(Architecture* arch, uint64_t addr);
		std::set<size_t> GetLiftedILFlagUsesForDefinition(size_t i, uint32_t flag);
		std::set<size_t> GetLiftedILFlagDefinitionsForUse(size_t i, uint32_t flag);
		std::set<uint32_t> GetFlagsReadByLiftedILInstruction(size_t i);
		std::set<uint32_t> GetFlagsWrittenByLiftedILInstruction(size_t i);

		Ref<MediumLevelILFunction> GetMediumLevelIL() const;

		Ref<Type> GetType() const;
		Confidence<Ref<Type>> GetReturnType() const;
		Confidence<std::vector<uint32_t>> GetReturnRegisters() const;
		Confidence<Ref<CallingConvention>> GetCallingConvention() const;
		Confidence<std::vector<Variable>> GetParameterVariables() const;
		Confidence<bool> HasVariableArguments() const;
		Confidence<size_t> GetStackAdjustment() const;
		std::map<uint32_t, Confidence<int32_t>> GetRegisterStackAdjustments() const;
		Confidence<std::set<uint32_t>> GetClobberedRegisters() const;

		void SetAutoType(Type* type);
		void SetAutoReturnType(const Confidence<Ref<Type>>& type);
		void SetAutoReturnRegisters(const Confidence<std::vector<uint32_t>>& returnRegs);
		void SetAutoCallingConvention(const Confidence<Ref<CallingConvention>>& convention);
		void SetAutoParameterVariables(const Confidence<std::vector<Variable>>& vars);
		void SetAutoHasVariableArguments(const Confidence<bool>& varArgs);
		void SetAutoCanReturn(const Confidence<bool>& returns);
		void SetAutoStackAdjustment(const Confidence<size_t>& stackAdjust);
		void SetAutoRegisterStackAdjustments(const std::map<uint32_t, Confidence<int32_t>>& regStackAdjust);
		void SetAutoClobberedRegisters(const Confidence<std::set<uint32_t>>& clobbered);

		void SetUserType(Type* type);
		void SetReturnType(const Confidence<Ref<Type>>& type);
		void SetReturnRegisters(const Confidence<std::vector<uint32_t>>& returnRegs);
		void SetCallingConvention(const Confidence<Ref<CallingConvention>>& convention);
		void SetParameterVariables(const Confidence<std::vector<Variable>>& vars);
		void SetHasVariableArguments(const Confidence<bool>& varArgs);
		void SetCanReturn(const Confidence<bool>& returns);
		void SetStackAdjustment(const Confidence<size_t>& stackAdjust);
		void SetRegisterStackAdjustments(const std::map<uint32_t, Confidence<int32_t>>& regStackAdjust);
		void SetClobberedRegisters(const Confidence<std::set<uint32_t>>& clobbered);

		void ApplyImportedTypes(Symbol* sym);
		void ApplyAutoDiscoveredType(Type* type);

		Ref<FunctionGraph> CreateFunctionGraph();

		std::map<int64_t, std::vector<VariableNameAndType>> GetStackLayout();
		void CreateAutoStackVariable(int64_t offset, const Confidence<Ref<Type>>& type, const std::string& name);
		void CreateUserStackVariable(int64_t offset, const Confidence<Ref<Type>>& type, const std::string& name);
		void DeleteAutoStackVariable(int64_t offset);
		void DeleteUserStackVariable(int64_t offset);
		bool GetStackVariableAtFrameOffset(Architecture* arch, uint64_t addr, int64_t offset, VariableNameAndType& var);

		std::map<Variable, VariableNameAndType> GetVariables();
		void CreateAutoVariable(const Variable& var, const Confidence<Ref<Type>>& type, const std::string& name,
			bool ignoreDisjointUses = false);
		void CreateUserVariable(const Variable& var, const Confidence<Ref<Type>>& type, const std::string& name,
			bool ignoreDisjointUses = false);
		void DeleteAutoVariable(const Variable& var);
		void DeleteUserVariable(const Variable& var);
		Confidence<Ref<Type>> GetVariableType(const Variable& var);
		std::string GetVariableName(const Variable& var);

		void SetAutoIndirectBranches(Architecture* sourceArch, uint64_t source, const std::vector<ArchAndAddr>& branches);
		void SetUserIndirectBranches(Architecture* sourceArch, uint64_t source, const std::vector<ArchAndAddr>& branches);

		std::vector<IndirectBranchInfo> GetIndirectBranches();
		std::vector<IndirectBranchInfo> GetIndirectBranchesAt(Architecture* arch, uint64_t addr);

		void SetAutoCallStackAdjustment(Architecture* arch, uint64_t addr, const Confidence<size_t>& adjust);
		void SetAutoCallRegisterStackAdjustment(Architecture* arch, uint64_t addr,
			const std::map<uint32_t, Confidence<int32_t>>& adjust);
		void SetAutoCallRegisterStackAdjustment(Architecture* arch, uint64_t addr, uint32_t regStack,
			const Confidence<int32_t>& adjust);
		void SetUserCallStackAdjustment(Architecture* arch, uint64_t addr, const Confidence<size_t>& adjust);
		void SetUserCallRegisterStackAdjustment(Architecture* arch, uint64_t addr,
			const std::map<uint32_t, Confidence<int32_t>>& adjust);
		void SetUserCallRegisterStackAdjustment(Architecture* arch, uint64_t addr, uint32_t regStack,
			const Confidence<int32_t>& adjust);

		Confidence<size_t> GetCallStackAdjustment(Architecture* arch, uint64_t addr);
		std::map<uint32_t, Confidence<int32_t>> GetCallRegisterStackAdjustment(Architecture* arch, uint64_t addr);
		Confidence<int32_t> GetCallRegisterStackAdjustment(Architecture* arch, uint64_t addr, uint32_t regStack);

		std::vector<std::vector<InstructionTextToken>> GetBlockAnnotations(Architecture* arch, uint64_t addr);

		BNIntegerDisplayType GetIntegerConstantDisplayType(Architecture* arch, uint64_t instrAddr, uint64_t value,
			size_t operand);
		void SetIntegerConstantDisplayType(Architecture* arch, uint64_t instrAddr, uint64_t value, size_t operand,
			BNIntegerDisplayType type);

		BNHighlightColor GetInstructionHighlight(Architecture* arch, uint64_t addr);
		void SetAutoInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightColor color);
		void SetAutoInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightStandardColor color,
			uint8_t alpha = 255);
		void SetAutoInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightStandardColor color,
			BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha = 255);
		void SetAutoInstructionHighlight(Architecture* arch, uint64_t addr, uint8_t r, uint8_t g, uint8_t b,
			uint8_t alpha = 255);
		void SetUserInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightColor color);
		void SetUserInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightStandardColor color,
			uint8_t alpha = 255);
		void SetUserInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightStandardColor color,
			BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha = 255);
		void SetUserInstructionHighlight(Architecture* arch, uint64_t addr, uint8_t r, uint8_t g, uint8_t b,
			uint8_t alpha = 255);

		void Reanalyze();

		void RequestAdvancedAnalysisData();
		void ReleaseAdvancedAnalysisData();
		void ReleaseAdvancedAnalysisData(size_t count);

		std::map<std::string, double> GetAnalysisPerformanceInfo();

		std::vector<DisassemblyTextLine> GetTypeTokens(DisassemblySettings* settings = nullptr);

		Confidence<RegisterValue> GetGlobalPointerValue() const;
		Confidence<RegisterValue> GetRegisterValueAtExit(uint32_t reg) const;

		bool IsFunctionTooLarge();
		bool IsAnalysisSkipped();
		BNFunctionAnalysisSkipOverride GetAnalysisSkipOverride();
		void SetAnalysisSkipOverride(BNFunctionAnalysisSkipOverride skip);
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

	struct FunctionGraphEdge
	{
		BNBranchType type;
		Ref<BasicBlock> target;
		std::vector<BNPoint> points;
		bool backEdge;
	};

	class FunctionGraphBlock: public CoreRefCountObject<BNFunctionGraphBlock,
		BNNewFunctionGraphBlockReference, BNFreeFunctionGraphBlock>
	{
		std::vector<DisassemblyTextLine> m_cachedLines;
		std::vector<FunctionGraphEdge> m_cachedEdges;
		bool m_cachedLinesValid, m_cachedEdgesValid;

	public:
		FunctionGraphBlock(BNFunctionGraphBlock* block);

		Ref<BasicBlock> GetBasicBlock() const;
		Ref<Architecture> GetArchitecture() const;
		uint64_t GetStart() const;
		uint64_t GetEnd() const;
		int GetX() const;
		int GetY() const;
		int GetWidth() const;
		int GetHeight() const;

		const std::vector<DisassemblyTextLine>& GetLines();
		const std::vector<FunctionGraphEdge>& GetOutgoingEdges();
	};

	class FunctionGraph: public RefCountObject
	{
		BNFunctionGraph* m_graph;
		std::function<void()> m_completeFunc;
		std::map<BNFunctionGraphBlock*, Ref<FunctionGraphBlock>> m_cachedBlocks;

		static void CompleteCallback(void* ctxt);

	public:
		FunctionGraph(BNFunctionGraph* graph);
		~FunctionGraph();

		BNFunctionGraph* GetGraphObject() const { return m_graph; }

		Ref<Function> GetFunction() const;

		int GetHorizontalBlockMargin() const;
		int GetVerticalBlockMargin() const;
		void SetBlockMargins(int horiz, int vert);

		Ref<DisassemblySettings> GetSettings();

		void StartLayout(BNFunctionGraphType = NormalFunctionGraph);
		bool IsLayoutComplete();
		void OnComplete(const std::function<void()>& func);
		void Abort();

		std::vector<Ref<FunctionGraphBlock>> GetBlocks();
		bool HasBlocks() const;

		int GetWidth() const;
		int GetHeight() const;
		std::vector<Ref<FunctionGraphBlock>> GetBlocksInRegion(int left, int top, int right, int bottom);

		bool IsOptionSet(BNDisassemblyOption option) const;
		void SetOption(BNDisassemblyOption option, bool state = true);

		bool IsILGraph() const;
		bool IsLowLevelILGraph() const;
		bool IsMediumLevelILGraph() const;
		Ref<LowLevelILFunction> GetLowLevelILFunction() const;
		Ref<MediumLevelILFunction> GetMediumLevelILFunction() const;
	};

	struct LowLevelILLabel: public BNLowLevelILLabel
	{
		LowLevelILLabel();
	};

	struct ILSourceLocation
	{
		uint64_t address;
		uint32_t sourceOperand;
		bool valid;

		ILSourceLocation(): valid(false)
		{
		}

		ILSourceLocation(uint64_t addr, uint32_t operand): address(addr), sourceOperand(operand), valid(true)
		{
		}

		ILSourceLocation(const BNLowLevelILInstruction& instr):
			address(instr.address), sourceOperand(instr.sourceOperand), valid(true)
		{
		}

		ILSourceLocation(const BNMediumLevelILInstruction& instr):
			address(instr.address), sourceOperand(instr.sourceOperand), valid(true)
		{
		}
	};

	struct LowLevelILInstruction;
	struct RegisterOrFlag;
	struct SSARegister;
	struct SSARegisterStack;
	struct SSAFlag;
	struct SSARegisterOrFlag;

	class LowLevelILFunction: public CoreRefCountObject<BNLowLevelILFunction,
		BNNewLowLevelILFunctionReference, BNFreeLowLevelILFunction>
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

		ExprId AddExpr(BNLowLevelILOperation operation, size_t size, uint32_t flags,
			ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0);
		ExprId AddExprWithLocation(BNLowLevelILOperation operation, uint64_t addr, uint32_t sourceOperand,
			size_t size, uint32_t flags, ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0);
		ExprId AddExprWithLocation(BNLowLevelILOperation operation, const ILSourceLocation& loc,
			size_t size, uint32_t flags, ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0);
		ExprId AddInstruction(ExprId expr);

		ExprId Nop(const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegister(size_t size, uint32_t reg, ExprId val, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterSplit(size_t size, uint32_t high, uint32_t low, ExprId val, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterSSA(size_t size, const SSARegister& reg, ExprId val,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterSSAPartial(size_t size, const SSARegister& fullReg, uint32_t partialReg, ExprId val,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterSplitSSA(size_t size, const SSARegister& high, const SSARegister& low, ExprId val,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterStackTopRelative(size_t size, uint32_t regStack, ExprId entry, ExprId val,
			uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackPush(size_t size, uint32_t regStack, ExprId val, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterStackTopRelativeSSA(size_t size, uint32_t regStack, size_t destVersion, size_t srcVersion,
			ExprId entry, const SSARegister& top, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterStackAbsoluteSSA(size_t size, uint32_t regStack, size_t destVersion, size_t srcVersion,
			uint32_t reg, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetFlag(uint32_t flag, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetFlagSSA(const SSAFlag& flag, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Load(size_t size, ExprId addr, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId LoadSSA(size_t size, ExprId addr, size_t sourceMemoryVer,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Store(size_t size, ExprId addr, ExprId val, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId StoreSSA(size_t size, ExprId addr, ExprId val, size_t newMemoryVer, size_t prevMemoryVer,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Push(size_t size, ExprId val, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Pop(size_t size, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Register(size_t size, uint32_t reg, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterSSA(size_t size, const SSARegister& reg, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterSSAPartial(size_t size, const SSARegister& fullReg, uint32_t partialReg,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterSplit(size_t size, uint32_t high, uint32_t low, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterSplitSSA(size_t size, const SSARegister& high, const SSARegister& low,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackTopRelative(size_t size, uint32_t regStack, ExprId entry,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackPop(size_t size, uint32_t regStack, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackFreeReg(uint32_t reg, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackFreeTopRelative(uint32_t regStack, ExprId entry,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackTopRelativeSSA(size_t size, const SSARegisterStack& regStack, ExprId entry,
			const SSARegister& top, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackAbsoluteSSA(size_t size, const SSARegisterStack& regStack, uint32_t reg,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackFreeTopRelativeSSA(uint32_t regStack, size_t destVersion, size_t srcVersion,
			ExprId entry, const SSARegister& top, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackFreeAbsoluteSSA(uint32_t regStack, size_t destVersion, size_t srcVersion,
			uint32_t reg, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Const(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ConstPointer(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstRaw(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstSingle(float val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstDouble(double val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Flag(uint32_t flag, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagSSA(const SSAFlag& flag, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagBit(size_t size, uint32_t flag, uint32_t bitIndex,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagBitSSA(size_t size, const SSAFlag& flag, uint32_t bitIndex,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Add(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddCarry(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Sub(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SubBorrow(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId And(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Or(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Xor(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId ShiftLeft(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId LogicalShiftRight(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId ArithShiftRight(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateLeft(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateLeftCarry(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateRight(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateRightCarry(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Mult(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId MultDoublePrecUnsigned(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId MultDoublePrecSigned(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivUnsigned(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivDoublePrecUnsigned(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivSigned(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivDoublePrecSigned(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModUnsigned(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModDoublePrecUnsigned(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModSigned(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModDoublePrecSigned(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Neg(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Not(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SignExtend(size_t size, ExprId a, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId ZeroExtend(size_t size, ExprId a, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId LowPart(size_t size, ExprId a, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Jump(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId JumpTo(ExprId dest, const std::vector<BNLowLevelILLabel*>& targets,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Call(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallStackAdjust(ExprId dest, size_t adjust, const std::map<uint32_t, int32_t>& regStackAdjust,
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
		ExprId FlagCondition(BNLowLevelILFlagCondition cond, uint32_t semClass = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagGroup(uint32_t semGroup, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareEqual(size_t size, ExprId a, ExprId b,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareNotEqual(size_t size, ExprId a, ExprId b,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedLessThan(size_t size, ExprId a, ExprId b,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedLessThan(size_t size, ExprId a, ExprId b,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedLessEqual(size_t size, ExprId a, ExprId b,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedLessEqual(size_t size, ExprId a, ExprId b,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedGreaterEqual(size_t size, ExprId a, ExprId b,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedGreaterEqual(size_t size, ExprId a, ExprId b,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedGreaterThan(size_t size, ExprId a, ExprId b,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedGreaterThan(size_t size, ExprId a, ExprId b,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId TestBit(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId BoolToInt(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SystemCall(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Intrinsic(const std::vector<RegisterOrFlag>& outputs, uint32_t intrinsic,
			const std::vector<ExprId>& params, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId IntrinsicSSA(const std::vector<SSARegisterOrFlag>& outputs, uint32_t intrinsic,
			const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Breakpoint(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Trap(uint32_t num, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Undefined(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Unimplemented(const ILSourceLocation& loc = ILSourceLocation());
		ExprId UnimplementedMemoryRef(size_t size, ExprId addr, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterPhi(const SSARegister& dest, const std::vector<SSARegister>& sources,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackPhi(const SSARegisterStack& dest, const std::vector<SSARegisterStack>& sources,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagPhi(const SSAFlag& dest, const std::vector<SSAFlag>& sources,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId MemoryPhi(size_t dest, const std::vector<size_t>& sources,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatAdd(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatSub(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatMult(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatDiv(size_t size, ExprId a, ExprId b, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatSqrt(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatNeg(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatAbs(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatToInt(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId IntToFloat(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConvert(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RoundToInt(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Floor(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Ceil(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatTrunc(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareNotEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareLessThan(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareLessEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareGreaterEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareGreaterThan(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareOrdered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareUnordered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		ExprId Goto(BNLowLevelILLabel& label, const ILSourceLocation& loc = ILSourceLocation());
		ExprId If(ExprId operand, BNLowLevelILLabel& t, BNLowLevelILLabel& f,
			const ILSourceLocation& loc = ILSourceLocation());
		void MarkLabel(BNLowLevelILLabel& label);

		std::vector<uint64_t> GetOperandList(ExprId i, size_t listOperand);
		ExprId AddLabelList(const std::vector<BNLowLevelILLabel*>& labels);
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
		ExprId GetExprForRegisterOrConstantOperation(BNLowLevelILOperation op, size_t size,
			BNRegisterOrConstant* operands, size_t operandCount);

		ExprId Operand(uint32_t n, ExprId expr);

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

		bool GetExprText(Architecture* arch, ExprId expr, std::vector<InstructionTextToken>& tokens);
		bool GetInstructionText(Function* func, Architecture* arch, size_t i,
			std::vector<InstructionTextToken>& tokens);

		uint32_t GetTemporaryRegisterCount();
		uint32_t GetTemporaryFlagCount();

		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;

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
		PossibleValueSet GetPossibleExprValues(size_t expr);
		PossibleValueSet GetPossibleExprValues(const LowLevelILInstruction& expr);

		RegisterValue GetRegisterValueAtInstruction(uint32_t reg, size_t instr);
		RegisterValue GetRegisterValueAfterInstruction(uint32_t reg, size_t instr);
		PossibleValueSet GetPossibleRegisterValuesAtInstruction(uint32_t reg, size_t instr);
		PossibleValueSet GetPossibleRegisterValuesAfterInstruction(uint32_t reg, size_t instr);
		RegisterValue GetFlagValueAtInstruction(uint32_t flag, size_t instr);
		RegisterValue GetFlagValueAfterInstruction(uint32_t flag, size_t instr);
		PossibleValueSet GetPossibleFlagValuesAtInstruction(uint32_t flag, size_t instr);
		PossibleValueSet GetPossibleFlagValuesAfterInstruction(uint32_t flag, size_t instr);
		RegisterValue GetStackContentsAtInstruction(int32_t offset, size_t len, size_t instr);
		RegisterValue GetStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr);
		PossibleValueSet GetPossibleStackContentsAtInstruction(int32_t offset, size_t len, size_t instr);
		PossibleValueSet GetPossibleStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr);

		Ref<MediumLevelILFunction> GetMediumLevelIL() const;
		Ref<MediumLevelILFunction> GetMappedMediumLevelIL() const;
		size_t GetMediumLevelILInstructionIndex(size_t instr) const;
		size_t GetMediumLevelILExprIndex(size_t expr) const;
		size_t GetMappedMediumLevelILInstructionIndex(size_t instr) const;
		size_t GetMappedMediumLevelILExprIndex(size_t expr) const;
	};

	struct MediumLevelILLabel: public BNMediumLevelILLabel
	{
		MediumLevelILLabel();
	};

	struct MediumLevelILInstruction;
	struct SSAVariable;

	class MediumLevelILFunction: public CoreRefCountObject<BNMediumLevelILFunction,
		BNNewMediumLevelILFunctionReference, BNFreeMediumLevelILFunction>
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

		ExprId AddExpr(BNMediumLevelILOperation operation, size_t size,
			ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0, ExprId e = 0);
		ExprId AddExprWithLocation(BNMediumLevelILOperation operation, uint64_t addr, uint32_t sourceOperand,
			size_t size, ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0, ExprId e = 0);
		ExprId AddExprWithLocation(BNMediumLevelILOperation operation, const ILSourceLocation& loc,
			size_t size, ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0, ExprId e = 0);

		ExprId Nop(const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVar(size_t size, const Variable& dest, ExprId src,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarField(size_t size, const Variable& dest, uint64_t offset, ExprId src,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarSplit(size_t size, const Variable& high, const Variable& low, ExprId src,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarSSA(size_t size, const SSAVariable& dest, ExprId src,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarSSAField(size_t size, const Variable& dest, size_t newVersion, size_t prevVersion,
			uint64_t offset, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarSSASplit(size_t size, const SSAVariable& high, const SSAVariable& low, ExprId src,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarAliased(size_t size, const Variable& dest, size_t newMemVersion, size_t prevMemVersion,
			ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarAliasedField(size_t size, const Variable& dest, size_t newMemVersion, size_t prevMemVersion,
			uint64_t offset, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Load(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LoadStruct(size_t size, ExprId src, uint64_t offset,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId LoadSSA(size_t size, ExprId src, size_t memVersion,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId LoadStructSSA(size_t size, ExprId src, uint64_t offset, size_t memVersion,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Store(size_t size, ExprId dest, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId StoreStruct(size_t size, ExprId dest, uint64_t offset, ExprId src,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId StoreSSA(size_t size, ExprId dest, size_t newMemVersion, size_t prevMemVersion, ExprId src,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId StoreStructSSA(size_t size, ExprId dest, uint64_t offset,
			size_t newMemVersion, size_t prevMemVersion, ExprId src,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Var(size_t size, const Variable& src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarField(size_t size, const Variable& src, uint64_t offset,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarSplit(size_t size, const Variable& high, const Variable& low,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarSSA(size_t size, const SSAVariable& src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarSSAField(size_t size, const SSAVariable& src, uint64_t offset,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarAliased(size_t size, const Variable& src, size_t memVersion,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarAliasedField(size_t size, const Variable& src, size_t memVersion, uint64_t offset,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarSplitSSA(size_t size, const SSAVariable& high, const SSAVariable& low,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddressOf(const Variable& var, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddressOfField(const Variable& var, uint64_t offset,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Const(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ConstPointer(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstRaw(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstSingle(float val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstDouble(double val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ImportedAddress(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Add(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddWithCarry(size_t size, ExprId left, ExprId right, ExprId carry,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Sub(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SubWithBorrow(size_t size, ExprId left, ExprId right, ExprId carry,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId And(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Or(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Xor(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ShiftLeft(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId LogicalShiftRight(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId ArithShiftRight(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateLeft(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateLeftCarry(size_t size, ExprId left, ExprId right, ExprId carry,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateRight(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateRightCarry(size_t size, ExprId left, ExprId right, ExprId carry,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Mult(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MultDoublePrecSigned(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId MultDoublePrecUnsigned(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivSigned(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivUnsigned(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivDoublePrecSigned(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivDoublePrecUnsigned(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModSigned(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModUnsigned(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModDoublePrecSigned(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModDoublePrecUnsigned(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Neg(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Not(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SignExtend(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ZeroExtend(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LowPart(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Jump(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId JumpTo(ExprId dest, const std::vector<BNMediumLevelILLabel*>& targets,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Call(const std::vector<Variable>& output, ExprId dest, const std::vector<ExprId>& params,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallUntyped(const std::vector<Variable>& output, ExprId dest, const std::vector<Variable>& params,
			ExprId stack, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Syscall(const std::vector<Variable>& output, const std::vector<ExprId>& params,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SyscallUntyped(const std::vector<Variable>& output, const std::vector<Variable>& params,
			ExprId stack, const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCall(const std::vector<Variable>& output, ExprId dest, const std::vector<ExprId>& params,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCallUntyped(const std::vector<Variable>& output, ExprId dest, const std::vector<Variable>& params,
			ExprId stack, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallSSA(const std::vector<SSAVariable>& output, ExprId dest, const std::vector<ExprId>& params,
			size_t newMemVersion, size_t prevMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallUntypedSSA(const std::vector<SSAVariable>& output, ExprId dest,
			const std::vector<SSAVariable>& params, size_t newMemVersion, size_t prevMemVersion,
			ExprId stack, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SyscallSSA(const std::vector<SSAVariable>& output, const std::vector<ExprId>& params,
			size_t newMemVersion, size_t prevMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SyscallUntypedSSA(const std::vector<SSAVariable>& output,
			const std::vector<SSAVariable>& params, size_t newMemVersion, size_t prevMemVersion,
			ExprId stack, const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCallSSA(const std::vector<SSAVariable>& output, ExprId dest, const std::vector<ExprId>& params,
			size_t newMemVersion, size_t prevMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCallUntypedSSA(const std::vector<SSAVariable>& output, ExprId dest,
			const std::vector<SSAVariable>& params, size_t newMemVersion, size_t prevMemVersion,
			ExprId stack, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Return(const std::vector<ExprId>& sources, const ILSourceLocation& loc = ILSourceLocation());
		ExprId NoReturn(const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareEqual(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareNotEqual(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedLessThan(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedLessThan(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedLessEqual(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedLessEqual(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedGreaterEqual(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedGreaterEqual(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedGreaterThan(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedGreaterThan(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId TestBit(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId BoolToInt(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddOverflow(size_t size, ExprId left, ExprId right,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Breakpoint(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Trap(int64_t vector, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Intrinsic(const std::vector<Variable>& outputs, uint32_t intrinsic,
			const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId IntrinsicSSA(const std::vector<SSAVariable>& outputs, uint32_t intrinsic,
			const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FreeVarSlot(const Variable& var, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FreeVarSlotSSA(const Variable& var, size_t newVersion, size_t prevVersion,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Undefined(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Unimplemented(const ILSourceLocation& loc = ILSourceLocation());
		ExprId UnimplementedMemoryRef(size_t size, ExprId target,
			const ILSourceLocation& loc = ILSourceLocation());
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
		ExprId FloatCompareGreaterEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareGreaterThan(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareOrdered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareUnordered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		ExprId Goto(BNMediumLevelILLabel& label, const ILSourceLocation& loc = ILSourceLocation());
		ExprId If(ExprId operand, BNMediumLevelILLabel& t, BNMediumLevelILLabel& f,
			const ILSourceLocation& loc = ILSourceLocation());
		void MarkLabel(BNMediumLevelILLabel& label);

		ExprId AddInstruction(ExprId expr);

		std::vector<uint64_t> GetOperandList(ExprId i, size_t listOperand);
		ExprId AddLabelList(const std::vector<BNMediumLevelILLabel*>& labels);
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

		bool GetExprText(Architecture* arch, ExprId expr, std::vector<InstructionTextToken>& tokens);
		bool GetInstructionText(Function* func, Architecture* arch, size_t i,
			std::vector<InstructionTextToken>& tokens);

		void VisitInstructions(const std::function<void(BasicBlock* block, const MediumLevelILInstruction& instr)>& func);
		void VisitAllExprs(const std::function<bool(BasicBlock* block, const MediumLevelILInstruction& expr)>& func);

		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;

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
		PossibleValueSet GetPossibleSSAVarValues(const SSAVariable& var, size_t instr);
		PossibleValueSet GetPossibleExprValues(size_t expr);
		PossibleValueSet GetPossibleExprValues(const MediumLevelILInstruction& expr);

		size_t GetSSAVarVersionAtInstruction(const Variable& var, size_t instr) const;
		size_t GetSSAMemoryVersionAtInstruction(size_t instr) const;
		Variable GetVariableForRegisterAtInstruction(uint32_t reg, size_t instr) const;
		Variable GetVariableForFlagAtInstruction(uint32_t flag, size_t instr) const;
		Variable GetVariableForStackLocationAtInstruction(int64_t offset, size_t instr) const;

		RegisterValue GetRegisterValueAtInstruction(uint32_t reg, size_t instr);
		RegisterValue GetRegisterValueAfterInstruction(uint32_t reg, size_t instr);
		PossibleValueSet GetPossibleRegisterValuesAtInstruction(uint32_t reg, size_t instr);
		PossibleValueSet GetPossibleRegisterValuesAfterInstruction(uint32_t reg, size_t instr);
		RegisterValue GetFlagValueAtInstruction(uint32_t flag, size_t instr);
		RegisterValue GetFlagValueAfterInstruction(uint32_t flag, size_t instr);
		PossibleValueSet GetPossibleFlagValuesAtInstruction(uint32_t flag, size_t instr);
		PossibleValueSet GetPossibleFlagValuesAfterInstruction(uint32_t flag, size_t instr);
		RegisterValue GetStackContentsAtInstruction(int32_t offset, size_t len, size_t instr);
		RegisterValue GetStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr);
		PossibleValueSet GetPossibleStackContentsAtInstruction(int32_t offset, size_t len, size_t instr);
		PossibleValueSet GetPossibleStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr);

		BNILBranchDependence GetBranchDependenceAtInstruction(size_t curInstr, size_t branchInstr) const;
		std::unordered_map<size_t, BNILBranchDependence> GetAllBranchDependenceAtInstruction(size_t instr) const;

		Ref<LowLevelILFunction> GetLowLevelIL() const;
		size_t GetLowLevelILInstructionIndex(size_t instr) const;
		size_t GetLowLevelILExprIndex(size_t expr) const;

		Confidence<Ref<Type>> GetExprType(size_t expr);
		Confidence<Ref<Type>> GetExprType(const MediumLevelILInstruction& expr);
	};

	class FunctionRecognizer
	{
		static bool RecognizeLowLevelILCallback(void* ctxt, BNBinaryView* data, BNFunction* func, BNLowLevelILFunction* il);
		static bool RecognizeMediumLevelILCallback(void* ctxt, BNBinaryView* data, BNFunction* func, BNMediumLevelILFunction* il);

	public:
		FunctionRecognizer();

		static void RegisterGlobalRecognizer(FunctionRecognizer* recog);
		static void RegisterArchitectureFunctionRecognizer(Architecture* arch, FunctionRecognizer* recog);

		virtual bool RecognizeLowLevelIL(BinaryView* data, Function* func, LowLevelILFunction* il);
		virtual bool RecognizeMediumLevelIL(BinaryView* data, Function* func, MediumLevelILFunction* il);
	};

	class UpdateException: public std::exception
	{
		const std::string m_desc;
	public:
		UpdateException(const std::string& desc): std::exception(), m_desc(desc) {}
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
		BNUpdateResult UpdateToVersion(const std::string& version,
		                               const std::function<bool(uint64_t progress, uint64_t total)>& progress);
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
		Ref<BinaryView> view;
		uint64_t address, length;
		size_t instrIndex;
		Ref<Function> function;
		Ref<LowLevelILFunction> lowLevelILFunction;
		Ref<MediumLevelILFunction> mediumLevelILFunction;

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

		static void DefaultPluginCommandActionCallback(void* ctxt, BNBinaryView* view);
		static void AddressPluginCommandActionCallback(void* ctxt, BNBinaryView* view, uint64_t addr);
		static void RangePluginCommandActionCallback(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len);
		static void FunctionPluginCommandActionCallback(void* ctxt, BNBinaryView* view, BNFunction* func);
		static void LowLevelILFunctionPluginCommandActionCallback(void* ctxt, BNBinaryView* view,
			BNLowLevelILFunction* func);
		static void LowLevelILInstructionPluginCommandActionCallback(void* ctxt, BNBinaryView* view,
			BNLowLevelILFunction* func, size_t instr);
		static void MediumLevelILFunctionPluginCommandActionCallback(void* ctxt, BNBinaryView* view,
			BNMediumLevelILFunction* func);
		static void MediumLevelILInstructionPluginCommandActionCallback(void* ctxt, BNBinaryView* view,
			BNMediumLevelILFunction* func, size_t instr);

		static bool DefaultPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view);
		static bool AddressPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, uint64_t addr);
		static bool RangePluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len);
		static bool FunctionPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, BNFunction* func);
		static bool LowLevelILFunctionPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view,
			BNLowLevelILFunction* func);
		static bool LowLevelILInstructionPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view,
			BNLowLevelILFunction* func, size_t instr);
		static bool MediumLevelILFunctionPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view,
			BNMediumLevelILFunction* func);
		static bool MediumLevelILInstructionPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view,
			BNMediumLevelILFunction* func, size_t instr);

	public:
		PluginCommand(const BNPluginCommand& cmd);
		PluginCommand(const PluginCommand& cmd);
		~PluginCommand();

		PluginCommand& operator=(const PluginCommand& cmd);

		static void Register(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view)>& action);
		static void Register(const std::string& name, const std::string& description,
			const std::function<void(BinaryView* view)>& action,
			const std::function<bool(BinaryView* view)>& isValid);
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

		static std::vector<PluginCommand> GetList();
		static std::vector<PluginCommand> GetValidList(const PluginCommandContext& ctxt);

		std::string GetName() const { return m_command.name; }
		std::string GetDescription() const { return m_command.description; }

		bool IsValid(const PluginCommandContext& ctxt) const;
		void Execute(const PluginCommandContext& ctxt) const;
	};

	class CallingConvention: public CoreRefCountObject<BNCallingConvention,
		BNNewCallingConventionReference, BNFreeCallingConvention>
	{
	protected:
		CallingConvention(BNCallingConvention* cc);
		CallingConvention(Architecture* arch, const std::string& name);

		static void FreeCallback(void* ctxt);

		static uint32_t* GetCallerSavedRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetIntegerArgumentRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetFloatArgumentRegistersCallback(void* ctxt, size_t* count);
		static void FreeRegisterListCallback(void* ctxt, uint32_t* regs);

		static bool AreArgumentRegistersSharedIndexCallback(void* ctxt);
		static bool IsStackReservedForArgumentRegistersCallback(void* ctxt);
		static bool IsStackAdjustedOnReturnCallback(void* ctxt);

		static uint32_t GetIntegerReturnValueRegisterCallback(void* ctxt);
		static uint32_t GetHighIntegerReturnValueRegisterCallback(void* ctxt);
		static uint32_t GetFloatReturnValueRegisterCallback(void* ctxt);
		static uint32_t GetGlobalPointerRegisterCallback(void* ctxt);

		static uint32_t* GetImplicitlyDefinedRegistersCallback(void* ctxt, size_t* count);
		static void GetIncomingRegisterValueCallback(void* ctxt, uint32_t reg, BNFunction* func, BNRegisterValue* result);
		static void GetIncomingFlagValueCallback(void* ctxt, uint32_t reg, BNFunction* func, BNRegisterValue* result);

		static void GetIncomingVariableForParameterVariableCallback(void* ctxt, const BNVariable* var,
			BNFunction* func, BNVariable* result);
		static void GetParameterVariableForIncomingVariableCallback(void* ctxt, const BNVariable* var,
			BNFunction* func, BNVariable* result);

	public:
		Ref<Architecture> GetArchitecture() const;
		std::string GetName() const;

		virtual std::vector<uint32_t> GetCallerSavedRegisters();

		virtual std::vector<uint32_t> GetIntegerArgumentRegisters();
		virtual std::vector<uint32_t> GetFloatArgumentRegisters();
		virtual bool AreArgumentRegistersSharedIndex();
		virtual bool IsStackReservedForArgumentRegisters();
		virtual bool IsStackAdjustedOnReturn();

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

	class CoreCallingConvention: public CallingConvention
	{
	public:
		CoreCallingConvention(BNCallingConvention* cc);

		virtual std::vector<uint32_t> GetCallerSavedRegisters() override;

		virtual std::vector<uint32_t> GetIntegerArgumentRegisters() override;
		virtual std::vector<uint32_t> GetFloatArgumentRegisters() override;
		virtual bool AreArgumentRegistersSharedIndex() override;
		virtual bool IsStackReservedForArgumentRegisters() override;
		virtual bool IsStackAdjustedOnReturn() override;

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
	class Platform: public CoreRefCountObject<BNPlatform, BNNewPlatformReference, BNFreePlatform>
	{
	protected:
		Platform(Architecture* arch, const std::string& name);

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
		Ref<Type> GetFunctionByName(const QualifiedName& name);
		std::string GetSystemCallName(uint32_t n);
		Ref<Type> GetSystemCallType(uint32_t n);

		std::string GenerateAutoPlatformTypeId(const QualifiedName& name);
		Ref<NamedTypeReference> GenerateAutoPlatformTypeReference(BNNamedTypeReferenceClass cls,
			const QualifiedName& name);
		std::string GetAutoPlatformTypeIdSource();

		bool ParseTypesFromSource(const std::string& source, const std::string& fileName,
			std::map<QualifiedName, Ref<Type>>& types,
			std::map<QualifiedName, Ref<Type>>& variables,
			std::map<QualifiedName, Ref<Type>>& functions, std::string& errors,
			const std::vector<std::string>& includeDirs = std::vector<std::string>(),
			const std::string& autoTypeSource = "");
		bool ParseTypesFromSourceFile(const std::string& fileName,
			std::map<QualifiedName, Ref<Type>>& types,
			std::map<QualifiedName, Ref<Type>>& variables,
			std::map<QualifiedName, Ref<Type>>& functions, std::string& errors,
			const std::vector<std::string>& includeDirs = std::vector<std::string>(),
			const std::string& autoTypeSource = "");
	};

	// DownloadProvider
	class DownloadProvider;

	class DownloadInstance: public CoreRefCountObject<BNDownloadInstance, BNNewDownloadInstanceReference, BNFreeDownloadInstance>
	{
	protected:
		DownloadInstance(DownloadProvider* provider);
		DownloadInstance(BNDownloadInstance* instance);

		static void DestroyInstanceCallback(void* ctxt);
		static int PerformRequestCallback(void* ctxt, const char* url);

		virtual void DestroyInstance();

	public:
		virtual int PerformRequest(const std::string& url) = 0;

		int PerformRequest(const std::string& url, BNDownloadInstanceOutputCallbacks* callbacks);

		std::string GetError() const;
		void SetError(const std::string& error);
	};

	class CoreDownloadInstance: public DownloadInstance
	{
	public:
		CoreDownloadInstance(BNDownloadInstance* instance);

		virtual int PerformRequest(const std::string& url) override;
	};

	class DownloadProvider: public StaticCoreRefCountObject<BNDownloadProvider>
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

	class CoreDownloadProvider: public DownloadProvider
	{
	public:
		CoreDownloadProvider(BNDownloadProvider* provider);
		virtual Ref<DownloadInstance> CreateNewInstance() override;
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

	class ScriptingInstance: public CoreRefCountObject<BNScriptingInstance,
		BNNewScriptingInstanceReference, BNFreeScriptingInstance>
	{
	protected:
		ScriptingInstance(ScriptingProvider* provider);
		ScriptingInstance(BNScriptingInstance* instance);

		static void DestroyInstanceCallback(void* ctxt);
		static BNScriptingProviderExecuteResult ExecuteScriptInputCallback(void* ctxt, const char* input);
		static void SetCurrentBinaryViewCallback(void* ctxt, BNBinaryView* view);
		static void SetCurrentFunctionCallback(void* ctxt, BNFunction* func);
		static void SetCurrentBasicBlockCallback(void* ctxt, BNBasicBlock* block);
		static void SetCurrentAddressCallback(void* ctxt, uint64_t addr);
		static void SetCurrentSelectionCallback(void* ctxt, uint64_t begin, uint64_t end);

		virtual void DestroyInstance();

	public:
		virtual BNScriptingProviderExecuteResult ExecuteScriptInput(const std::string& input) = 0;
		virtual void SetCurrentBinaryView(BinaryView* view);
		virtual void SetCurrentFunction(Function* func);
		virtual void SetCurrentBasicBlock(BasicBlock* block);
		virtual void SetCurrentAddress(uint64_t addr);
		virtual void SetCurrentSelection(uint64_t begin, uint64_t end);

		void Output(const std::string& text);
		void Error(const std::string& text);
		void InputReadyStateChanged(BNScriptingProviderInputReadyState state);
		BNScriptingProviderInputReadyState GetInputReadyState();

		void RegisterOutputListener(ScriptingOutputListener* listener);
		void UnregisterOutputListener(ScriptingOutputListener* listener);
	};

	class CoreScriptingInstance: public ScriptingInstance
	{
	public:
		CoreScriptingInstance(BNScriptingInstance* instance);

		virtual BNScriptingProviderExecuteResult ExecuteScriptInput(const std::string& input) override;
		virtual void SetCurrentBinaryView(BinaryView* view) override;
		virtual void SetCurrentFunction(Function* func) override;
		virtual void SetCurrentBasicBlock(BasicBlock* block) override;
		virtual void SetCurrentAddress(uint64_t addr) override;
		virtual void SetCurrentSelection(uint64_t begin, uint64_t end) override;
	};

	class ScriptingProvider: public StaticCoreRefCountObject<BNScriptingProvider>
	{
		std::string m_nameForRegister;

	protected:
		ScriptingProvider(const std::string& name);
		ScriptingProvider(BNScriptingProvider* provider);

		static BNScriptingInstance* CreateInstanceCallback(void* ctxt);

	public:
		virtual Ref<ScriptingInstance> CreateNewInstance() = 0;

		static std::vector<Ref<ScriptingProvider>> GetList();
		static Ref<ScriptingProvider> GetByName(const std::string& name);
		static void Register(ScriptingProvider* provider);
	};

	class CoreScriptingProvider: public ScriptingProvider
	{
	public:
		CoreScriptingProvider(BNScriptingProvider* provider);
		virtual Ref<ScriptingInstance> CreateNewInstance() override;
	};

	class MainThreadAction: public CoreRefCountObject<BNMainThreadAction,
		BNNewMainThreadActionReference, BNFreeMainThreadAction>
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

	class BackgroundTask: public CoreRefCountObject<BNBackgroundTask,
		BNNewBackgroundTaskReference, BNFreeBackgroundTask>
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
		Ref<BinaryView> view; // For AddressFormField
		uint64_t currentAddress; // For AddressFormField
		std::vector<std::string> choices; // For ChoiceFormField
		std::string ext; // For OpenFileNameFormField, SaveFileNameFormField
		std::string defaultName; // For SaveFileNameFormField
		int64_t intResult;
		uint64_t addressResult;
		std::string stringResult;
		size_t indexResult;

		static FormInputField Label(const std::string& text);
		static FormInputField Separator();
		static FormInputField TextLine(const std::string& prompt);
		static FormInputField MultilineText(const std::string& prompt);
		static FormInputField Integer(const std::string& prompt);
		static FormInputField Address(const std::string& prompt, BinaryView* view = nullptr, uint64_t currentAddress = 0);
		static FormInputField Choice(const std::string& prompt, const std::vector<std::string>& choices);
		static FormInputField OpenFileName(const std::string& prompt, const std::string& ext);
		static FormInputField SaveFileName(const std::string& prompt, const std::string& ext,
			const std::string& defaultName = "");
		static FormInputField DirectoryName(const std::string& prompt, const std::string& defaultName = "");
	};

	class InteractionHandler
	{
	public:
		virtual void ShowPlainTextReport(Ref<BinaryView> view, const std::string& title, const std::string& contents) = 0;
		virtual void ShowMarkdownReport(Ref<BinaryView> view, const std::string& title, const std::string& contents,
			const std::string& plainText);
		virtual void ShowHTMLReport(Ref<BinaryView> view, const std::string& title, const std::string& contents,
			const std::string& plainText);

		virtual bool GetTextLineInput(std::string& result, const std::string& prompt, const std::string& title) = 0;
		virtual bool GetIntegerInput(int64_t& result, const std::string& prompt, const std::string& title);
		virtual bool GetAddressInput(uint64_t& result, const std::string& prompt, const std::string& title,
			Ref<BinaryView> view, uint64_t currentAddr);
		virtual bool GetChoiceInput(size_t& idx, const std::string& prompt, const std::string& title,
			const std::vector<std::string>& choices) = 0;
		virtual bool GetOpenFileNameInput(std::string& result, const std::string& prompt, const std::string& ext = "");
		virtual bool GetSaveFileNameInput(std::string& result, const std::string& prompt,
			const std::string& ext = "", const std::string& defaultName = "");
		virtual bool GetDirectoryNameInput(std::string& result, const std::string& prompt,
			const std::string& defaultName = "");
		virtual bool GetFormInput(std::vector<FormInputField>& fields, const std::string& title) = 0;

		virtual BNMessageBoxButtonResult ShowMessageBox(const std::string& title, const std::string& text,
			BNMessageBoxButtonSet buttons = OKButtonSet, BNMessageBoxIcon icon = InformationIcon) = 0;
	};

	typedef BNPluginOrigin PluginOrigin;
	typedef BNPluginUpdateStatus PluginUpdateStatus;
	typedef BNPluginType PluginType;

	class RepoPlugin: public CoreRefCountObject<BNRepoPlugin, BNNewPluginReference, BNFreePlugin>
	{
	public:
		RepoPlugin(BNRepoPlugin* plugin);
		std::string GetPath() const;
		bool IsInstalled() const;
		std::string GetPluginDirectory() const;
		void SetEnabled(bool enabled);
		bool IsEnabled() const;
		PluginUpdateStatus GetPluginUpdateStatus() const;
		std::string GetApi() const;
		std::string GetAuthor() const;
		std::string GetDescription() const;
		std::string GetLicense() const;
		std::string GetLicenseText() const;
		std::string GetLongdescription() const;
		std::string GetMinimimVersions() const;
		std::string GetName() const;
		std::vector<PluginType> GetPluginTypes() const;
		std::string GetUrl() const;
		std::string GetVersion() const;
	};

	class Repository: public CoreRefCountObject<BNRepository, BNNewRepositoryReference, BNFreeRepository>
	{
	public:
		Repository(BNRepository* repository);
		~Repository();
		std::string GetUrl() const;
		std::string GetRepoPath() const;
		std::string GetLocalReference() const;
		std::string GetRemoteReference() const;
		std::vector<Ref<RepoPlugin>> GetPlugins() const;
		bool IsInitialized() const;
		std::string GetPluginDirectory() const;
		Ref<RepoPlugin> GetPluginByPath(const std::string& pluginPath);
		std::string GetFullPath() const;
	};

	class RepositoryManager: public CoreRefCountObject<BNRepositoryManager, BNNewRepositoryManagerReference, BNFreeRepositoryManager>
	{
		bool m_core;
	public:
		RepositoryManager(const std::string& enabledPluginsPath);
		RepositoryManager(BNRepositoryManager* repoManager);
		RepositoryManager();
		~RepositoryManager();
		bool CheckForUpdates();
		std::vector<Ref<Repository>> GetRepositories();
		Ref<Repository> GetRepositoryByPath(const std::string& repoName);
		bool AddRepository(const std::string& url,
			const std::string& repoPath, // Relative path within the repositories directory
			const std::string& localReference="master",
			const std::string& remoteReference="origin");
		bool EnablePlugin(const std::string& repoName, const std::string& pluginPath);
		bool DisablePlugin(const std::string& repoName, const std::string& pluginPath);
		bool InstallPlugin(const std::string& repoName, const std::string& pluginPath);
		bool UninstallPlugin(const std::string& repoName, const std::string& pluginPath);
		Ref<Repository> GetDefaultRepository();
	};

	class Setting
	{
	public:
		static bool GetBool(const std::string& settingGroup, const std::string& name, bool defaultValue);
		static int64_t GetInteger(const std::string& settingGroup, const std::string& name, int64_t defaultValue=0);
		static std::string GetString(const std::string& settingGroup, const std::string& name, const std::string& defaultValue="");
		static std::vector<int64_t> GetIntegerList(const std::string& settingGroup, const std::string& name, const std::vector<int64_t>& defaultValue={});
		static std::vector<std::string> GetStringList(const std::string& settingGroup, const std::string& name, const std::vector<std::string>& defaultValue={});
		static double GetDouble(const std::string& settingGroup, const std::string& name, double defaultValue=0.0);

		static bool IsPresent(const std::string& settingGroup, const std::string& name);
		static bool IsBool(const std::string& settingGroup, const std::string& name);
		static bool IsInteger(const std::string& settingGroup, const std::string& name);
		static bool IsString(const std::string& settingGroup, const std::string& name);
		static bool IsIntegerList(const std::string& settingGroup, const std::string& name);
		static bool IsStringList(const std::string& settingGroup, const std::string& name);
		static bool IsDouble(const std::string& settingGroup, const std::string& name);

		static bool Set(const std::string& settingGroup,
			const std::string& name,
			bool value,
			bool autoFlush=true);
		static bool Set(const std::string& settingGroup,
			const std::string& name,
			int64_t value,
			bool autoFlush=true);
		static bool Set(const std::string& settingGroup,
			const std::string& name,
			const std::string& value,
			bool autoFlush=true);
		static bool Set(const std::string& settingGroup,
			const std::string& name,
			const std::vector<int64_t>& value,
			bool autoFlush=true);
		static bool Set(const std::string& settingGroup,
			const std::string& name,
			const std::vector<std::string>& value,
			bool autoFlush=true);
		static bool Set(const std::string& settingGroup,
			const std::string& name,
			double value,
			bool autoFlush=true);

		static bool RemoveSettingGroup(const std::string& settingGroup, bool autoFlush=true);
		static bool RemoveSetting(const std::string& settingGroup, const std::string& setting, bool autoFlush=true);
		static bool FlushSettings();
	};

	typedef BNMetadataType MetadataType;

	class Metadata: public CoreRefCountObject<BNMetadata, BNNewMetadataReference, BNFreeMetadata>
	{
	public:
		Metadata(BNMetadata* structuredData);
		Metadata(bool data);
		Metadata(const std::string& data);
		Metadata(uint64_t data);
		Metadata(int64_t data);
		Metadata(double data);
		Metadata(const std::vector<bool>& data);
		Metadata(const std::vector<std::string>& data);
		Metadata(const std::vector<uint64_t>& data);
		Metadata(const std::vector<int64_t>& data);
		Metadata(const std::vector<double>& data);
		Metadata(const std::vector<uint8_t>& data);
		Metadata(const std::vector<Ref<Metadata>>& data);
		Metadata(const std::map<std::string, Ref<Metadata>>& data);
		Metadata(MetadataType type);
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

		//For key-value data only
		Ref<Metadata> Get(const std::string& key);
		bool SetValueForKey(const std::string& key, Ref<Metadata> data);
		void RemoveKey(const std::string& key);

		//For array data only
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
}
