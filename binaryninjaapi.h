// Copyright (c) 2015-2016 Vector 35 LLC
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
#include <exception>
#include <functional>
#include <set>
#include <mutex>
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
	std::string GetBundledPluginDirectory();
	void SetBundledPluginDirectory(const std::string& path);
	std::string GetUserPluginDirectory();

	std::string GetPathRelativeToBundledPluginDirectory(const std::string& path);
	std::string GetPathRelativeToUserPluginDirectory(const std::string& path);

	bool ExecuteWorkerProcess(const std::string& path, const std::vector<std::string>& args, const DataBuffer& input,
	                          std::string& output, std::string& errors, bool stdoutIsText=false, bool stderrIsText=true);

	std::string GetVersionString();
	std::string GetProduct();
	std::string GetProductType();
	int GetLicenseCount();
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
		size_t size() const;

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
		uint64_t address;

		InstructionTextToken();
		InstructionTextToken(BNInstructionTextTokenType type, const std::string& text, uint64_t value = 0,
			size_t size = 0, size_t operand = BN_INVALID_OPERAND);
		InstructionTextToken(BNInstructionTextTokenType type, BNInstructionTextTokenContext context,
			const std::string& text, uint64_t address, uint64_t value = 0, size_t size = 0,
			size_t operand = BN_INVALID_OPERAND);
	};

	struct DisassemblyTextLine
	{
		uint64_t addr;
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
		uint64_t address;
		Ref<Type> type;
		bool autoDiscovered;
	};

	struct Segment
	{
		uint64_t start, length;
		uint64_t dataOffset, dataLength;
		uint32_t flags;
	};

	struct Section
	{
		std::string name, type;
		uint64_t start, length;
		std::string linkedSection, infoSection;
		uint64_t infoData;
		uint64_t align, entrySize;
	};

	struct QualifiedNameAndType;

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
		....\param len the number of bytes to read from offset and write to dest
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
		size_t GetAddressSize() const;

		bool IsExecutable() const;

		bool Save(FileAccessor* file);
		bool Save(const std::string& path);

		void RegisterNotification(BinaryDataNotification* notify);
		void UnregisterNotification(BinaryDataNotification* notify);

		void AddFunctionForAnalysis(Platform* platform, uint64_t addr);
		void AddEntryPointForAnalysis(Platform* platform, uint64_t start);
		void RemoveAnalysisFunction(Function* func);
		void CreateUserFunction(Platform* platform, uint64_t start);
		void RemoveUserFunction(Function* func);
		void UpdateAnalysis();
		void AbortAnalysis();

		void DefineDataVariable(uint64_t addr, Type* type);
		void DefineUserDataVariable(uint64_t addr, Type* type);
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

		void AddAutoSection(const std::string& name, uint64_t start, uint64_t length, const std::string& type = "",
			uint64_t align = 1, uint64_t entrySize = 0, const std::string& linkedSection = "",
			const std::string& infoSection = "", uint64_t infoData = 0);
		void RemoveAutoSection(const std::string& name);
		void AddUserSection(const std::string& name, uint64_t start, uint64_t length, const std::string& type = "",
			uint64_t align = 1, uint64_t entrySize = 0, const std::string& linkedSection = "",
			const std::string& infoSection = "", uint64_t infoData = 0);
		void RemoveUserSection(const std::string& name);
		std::vector<Section> GetSections();
		std::vector<Section> GetSectionsAt(uint64_t addr);
		bool GetSectionByName(const std::string& name, Section& result);

		std::vector<std::string> GetUniqueSectionNames(const std::vector<std::string>& names);

		std::vector<BNAddressRange> GetAllocatedRanges();
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
		std::string ReadString(size_t len);
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

	class LowLevelILFunction;
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
		static uint32_t* GetFullWidthRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetAllRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetAllFlagsCallback(void* ctxt, size_t* count);
		static uint32_t* GetAllFlagWriteTypesCallback(void* ctxt, size_t* count);
		static BNFlagRole GetFlagRoleCallback(void* ctxt, uint32_t flag);
		static uint32_t* GetFlagsRequiredForFlagConditionCallback(void* ctxt, BNLowLevelILFlagCondition cond, size_t* count);
		static uint32_t* GetFlagsWrittenByFlagWriteTypeCallback(void* ctxt, uint32_t writeType, size_t* count);
		static size_t GetFlagWriteLowLevelILCallback(void* ctxt, BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
			uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, BNLowLevelILFunction* il);
		static size_t GetFlagConditionLowLevelILCallback(void* ctxt, BNLowLevelILFlagCondition cond,
			BNLowLevelILFunction* il);
		static void FreeRegisterListCallback(void* ctxt, uint32_t* regs);
		static void GetRegisterInfoCallback(void* ctxt, uint32_t reg, BNRegisterInfo* result);
		static uint32_t GetStackPointerRegisterCallback(void* ctxt);
		static uint32_t GetLinkRegisterCallback(void* ctxt);

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

	public:
		Architecture(const std::string& name);

		static void Register(Architecture* arch);
		static Ref<Architecture> GetByName(const std::string& name);
		static std::vector<Ref<Architecture>> GetList();

		std::string GetName() const;

		virtual BNEndianness GetEndianness() const = 0;
		virtual size_t GetAddressSize() const = 0;
		virtual size_t GetDefaultIntegerSize() const;

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
		virtual std::vector<uint32_t> GetFullWidthRegisters();
		virtual std::vector<uint32_t> GetAllRegisters();
		virtual std::vector<uint32_t> GetAllFlags();
		virtual std::vector<uint32_t> GetAllFlagWriteTypes();
		virtual BNFlagRole GetFlagRole(uint32_t flag);
		virtual std::vector<uint32_t> GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond);
		virtual std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType);
		virtual ExprId GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
			uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il);
		ExprId GetDefaultFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
			uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il);
		virtual ExprId GetFlagConditionLowLevelIL(BNLowLevelILFlagCondition cond, LowLevelILFunction& il);
		virtual BNRegisterInfo GetRegisterInfo(uint32_t reg);
		virtual uint32_t GetStackPointerRegister();
		virtual uint32_t GetLinkRegister();
		std::vector<uint32_t> GetModifiedRegistersOnWrite(uint32_t reg);
		uint32_t GetRegisterByName(const std::string& name);

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
	};

	class CoreArchitecture: public Architecture
	{
	public:
		CoreArchitecture(BNArchitecture* arch);
		virtual BNEndianness GetEndianness() const override;
		virtual size_t GetAddressSize() const override;
		virtual size_t GetDefaultIntegerSize() const override;
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
		virtual std::vector<uint32_t> GetFullWidthRegisters() override;
		virtual std::vector<uint32_t> GetAllRegisters() override;
		virtual std::vector<uint32_t> GetAllFlags() override;
		virtual std::vector<uint32_t> GetAllFlagWriteTypes() override;
		virtual BNFlagRole GetFlagRole(uint32_t flag) override;
		virtual std::vector<uint32_t> GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond) override;
		virtual std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType) override;
		virtual ExprId GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
			uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il) override;
		virtual ExprId GetFlagConditionLowLevelIL(BNLowLevelILFlagCondition cond, LowLevelILFunction& il) override;
		virtual BNRegisterInfo GetRegisterInfo(uint32_t reg) override;
		virtual uint32_t GetStackPointerRegister() override;
		virtual uint32_t GetLinkRegister() override;

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

	class Structure;
	class NamedTypeReference;
	class Enumeration;

	struct NameAndType
	{
		std::string name;
		Ref<Type> type;
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
		bool IsSigned() const;
		bool IsConst() const;
		bool IsVolatile() const;
		bool IsFloat() const;
		Ref<Type> GetChildType() const;
		Ref<CallingConvention> GetCallingConvention() const;
		std::vector<NameAndType> GetParameters() const;
		bool HasVariableArguments() const;
		bool CanReturn() const;
		Ref<Structure> GetStructure() const;
		Ref<Enumeration> GetEnumeration() const;
		Ref<NamedTypeReference> GetNamedTypeReference() const;

		uint64_t GetElementCount() const;

		void SetFunctionCanReturn(bool canReturn);

		std::string GetString() const;
		std::string GetTypeAndName(const QualifiedName& name) const;
		std::string GetStringBeforeName() const;
		std::string GetStringAfterName() const;

		std::vector<InstructionTextToken> GetTokens() const;
		std::vector<InstructionTextToken> GetTokensBeforeName() const;
		std::vector<InstructionTextToken> GetTokensAfterName() const;

		Ref<Type> Duplicate() const;

		static Ref<Type> VoidType();
		static Ref<Type> BoolType();
		static Ref<Type> IntegerType(size_t width, bool sign, const std::string& altName = "");
		static Ref<Type> FloatType(size_t width, const std::string& typeName = "");
		static Ref<Type> StructureType(Structure* strct);
		static Ref<Type> NamedType(NamedTypeReference* ref, size_t width = 0, size_t align = 1);
		static Ref<Type> NamedType(const QualifiedName& name, Type* type);
		static Ref<Type> NamedType(const std::string& id, const QualifiedName& name, Type* type);
		static Ref<Type> NamedType(BinaryView* view, const QualifiedName& name);
		static Ref<Type> EnumerationType(Architecture* arch, Enumeration* enm, size_t width = 0, bool issigned = false);
		static Ref<Type> PointerType(Architecture* arch, Type* type, bool cnst = false, bool vltl = false,
		                             BNReferenceType refType = PointerReferenceType);
		static Ref<Type> ArrayType(Type* type, uint64_t elem);
		static Ref<Type> FunctionType(Type* returnValue, CallingConvention* callingConvention,
		                              const std::vector<NameAndType>& params, bool varArg = false);

 		static std::string GenerateAutoTypeId(const std::string& source, const QualifiedName& name);
		static std::string GenerateAutoDemangledTypeId(const QualifiedName& name);
		static std::string GetAutoDemangledTypeIdSource();
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

		std::vector<StructureMember> GetMembers() const;
		uint64_t GetWidth() const;
		void SetWidth(size_t width);
		size_t GetAlignment() const;
		void SetAlignment(size_t align);
		bool IsPacked() const;
		void SetPacked(bool packed);
		bool IsUnion() const;
		void SetUnion(bool u);

		void AddMember(Type* type, const std::string& name);
		void AddMemberAtOffset(Type* type, const std::string& name, uint64_t offset);
		void RemoveMember(size_t idx);
		void ReplaceMember(size_t idx, Type* type, const std::string& name);
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
	};

	struct StackVariable
	{
		Ref<Type> type;
		std::string name;
		int64_t offset;
		bool autoDefined;
	};

	struct StackVariableReference
	{
		uint32_t sourceOperand;
		Ref<Type> type;
		std::string name;
		int64_t startingOffset;
		int64_t referencedOffset;
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
		uint32_t reg; // For EntryValue and OffsetFromEntryValue, the original input register
		int64_t value; // Offset for OffsetFromEntryValue, StackFrameOffset or RangeValue, value of register for ConstantValue
		uint64_t rangeStart, rangeEnd, rangeStep; // Range of register, inclusive
		std::vector<LookupTableEntry> table;

		static RegisterValue FromAPIObject(BNRegisterValue& value);
	};

	class FunctionGraph;

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
		bool CanReturn() const;
		bool HasExplicitlyDefinedType() const;
		bool NeedsUpdate() const;

		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;
		Ref<BasicBlock> GetBasicBlockAtAddress(Architecture* arch, uint64_t addr) const;
		void MarkRecentUse();

		std::string GetCommentForAddress(uint64_t addr) const;
		std::vector<uint64_t> GetCommentedAddresses() const;
		void SetCommentForAddress(uint64_t addr, const std::string& comment);

		Ref<LowLevelILFunction> GetLowLevelIL() const;
		size_t GetLowLevelILForInstruction(Architecture* arch, uint64_t addr);
		std::vector<size_t> GetLowLevelILExitsForInstruction(Architecture* arch, uint64_t addr);
		RegisterValue GetRegisterValueAtInstruction(Architecture* arch, uint64_t addr, uint32_t reg);
		RegisterValue GetRegisterValueAfterInstruction(Architecture* arch, uint64_t addr, uint32_t reg);
		RegisterValue GetRegisterValueAtLowLevelILInstruction(size_t i, uint32_t reg);
		RegisterValue GetRegisterValueAfterLowLevelILInstruction(size_t i, uint32_t reg);
		RegisterValue GetStackContentsAtInstruction(Architecture* arch, uint64_t addr, int64_t offset, size_t size);
		RegisterValue GetStackContentsAfterInstruction(Architecture* arch, uint64_t addr, int64_t offset, size_t size);
		RegisterValue GetStackContentsAtLowLevelILInstruction(size_t i, int64_t offset, size_t size);
		RegisterValue GetStackContentsAfterLowLevelILInstruction(size_t i, int64_t offset, size_t size);
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

		Ref<Type> GetType() const;
		void SetAutoType(Type* type);
		void SetUserType(Type* type);
		void ApplyImportedTypes(Symbol* sym);
		void ApplyAutoDiscoveredType(Type* type);

		Ref<FunctionGraph> CreateFunctionGraph();

		std::map<int64_t, StackVariable> GetStackLayout();
		void CreateAutoStackVariable(int64_t offset, Ref<Type> type, const std::string& name);
		void CreateUserStackVariable(int64_t offset, Ref<Type> type, const std::string& name);
		void DeleteAutoStackVariable(int64_t offset);
		void DeleteUserStackVariable(int64_t offset);
		bool GetStackVariableAtFrameOffset(int64_t offset, StackVariable& var);

		void SetAutoIndirectBranches(Architecture* sourceArch, uint64_t source, const std::vector<ArchAndAddr>& branches);
		void SetUserIndirectBranches(Architecture* sourceArch, uint64_t source, const std::vector<ArchAndAddr>& branches);

		std::vector<IndirectBranchInfo> GetIndirectBranches();
		std::vector<IndirectBranchInfo> GetIndirectBranchesAt(Architecture* arch, uint64_t addr);

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

		int GetWidth() const;
		int GetHeight() const;
		std::vector<Ref<FunctionGraphBlock>> GetBlocksInRegion(int left, int top, int right, int bottom);

		bool IsOptionSet(BNDisassemblyOption option) const;
		void SetOption(BNDisassemblyOption option, bool state = true);
	};

	struct LowLevelILLabel: public BNLowLevelILLabel
	{
		LowLevelILLabel();
	};

	class LowLevelILFunction: public CoreRefCountObject<BNLowLevelILFunction,
		BNNewLowLevelILFunctionReference, BNFreeLowLevelILFunction>
	{
	public:
		LowLevelILFunction(Architecture* arch, Function* func = nullptr);
		LowLevelILFunction(BNLowLevelILFunction* func);

		uint64_t GetCurrentAddress() const;
		void SetCurrentAddress(Architecture* arch, uint64_t addr);
		size_t GetInstructionStart(Architecture* arch, uint64_t addr);

		void ClearIndirectBranches();
		void SetIndirectBranches(const std::vector<ArchAndAddr>& branches);

		ExprId AddExpr(BNLowLevelILOperation operation, size_t size, uint32_t flags,
		               ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0);
		ExprId AddInstruction(ExprId expr);

		ExprId Nop();
		ExprId SetRegister(size_t size, uint32_t reg, ExprId val, uint32_t flags = 0);
		ExprId SetRegisterSplit(size_t size, uint32_t high, uint32_t low, ExprId val);
		ExprId SetFlag(uint32_t flag, ExprId val);
		ExprId Load(size_t size, ExprId addr);
		ExprId Store(size_t size, ExprId addr, ExprId val);
		ExprId Push(size_t size, ExprId val);
		ExprId Pop(size_t size);
		ExprId Register(size_t size, uint32_t reg);
		ExprId Const(size_t size, uint64_t val);
		ExprId Flag(uint32_t reg);
		ExprId FlagBit(size_t size, uint32_t flag, uint32_t bitIndex);
		ExprId Add(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId AddCarry(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId Sub(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId SubBorrow(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId And(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId Or(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId Xor(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId ShiftLeft(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId LogicalShiftRight(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId ArithShiftRight(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId RotateLeft(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId RotateLeftCarry(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId RotateRight(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId RotateRightCarry(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId Mult(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId MultDoublePrecUnsigned(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId MultDoublePrecSigned(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId DivUnsigned(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId DivDoublePrecUnsigned(size_t size, ExprId high, ExprId low, ExprId div, uint32_t flags = 0);
		ExprId DivSigned(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId DivDoublePrecSigned(size_t size, ExprId high, ExprId low, ExprId div, uint32_t flags = 0);
		ExprId ModUnsigned(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId ModDoublePrecUnsigned(size_t size, ExprId high, ExprId low, ExprId div, uint32_t flags = 0);
		ExprId ModSigned(size_t size, ExprId a, ExprId b, uint32_t flags = 0);
		ExprId ModDoublePrecSigned(size_t size, ExprId high, ExprId low, ExprId div, uint32_t flags = 0);
		ExprId Neg(size_t size, ExprId a, uint32_t flags = 0);
		ExprId Not(size_t size, ExprId a, uint32_t flags = 0);
		ExprId SignExtend(size_t size, ExprId a);
		ExprId ZeroExtend(size_t size, ExprId a);
		ExprId Jump(ExprId dest);
		ExprId Call(ExprId dest);
		ExprId Return(size_t dest);
		ExprId NoReturn();
		ExprId FlagCondition(BNLowLevelILFlagCondition cond);
		ExprId CompareEqual(size_t size, ExprId a, ExprId b);
		ExprId CompareNotEqual(size_t size, ExprId a, ExprId b);
		ExprId CompareSignedLessThan(size_t size, ExprId a, ExprId b);
		ExprId CompareUnsignedLessThan(size_t size, ExprId a, ExprId b);
		ExprId CompareSignedLessEqual(size_t size, ExprId a, ExprId b);
		ExprId CompareUnsignedLessEqual(size_t size, ExprId a, ExprId b);
		ExprId CompareSignedGreaterEqual(size_t size, ExprId a, ExprId b);
		ExprId CompareUnsignedGreaterEqual(size_t size, ExprId a, ExprId b);
		ExprId CompareSignedGreaterThan(size_t size, ExprId a, ExprId b);
		ExprId CompareUnsignedGreaterThan(size_t size, ExprId a, ExprId b);
		ExprId TestBit(size_t size, ExprId a, ExprId b);
		ExprId BoolToInt(size_t size, ExprId a);
		ExprId SystemCall();
		ExprId Breakpoint();
		ExprId Trap(uint32_t num);
		ExprId Undefined();
		ExprId Unimplemented();
		ExprId UnimplementedMemoryRef(size_t size, ExprId addr);

		ExprId Goto(BNLowLevelILLabel& label);
		ExprId If(ExprId operand, BNLowLevelILLabel& t, BNLowLevelILLabel& f);
		void MarkLabel(BNLowLevelILLabel& label);

		std::vector<uint64_t> GetOperandList(ExprId i, size_t listOperand);
		ExprId AddLabelList(const std::vector<BNLowLevelILLabel*>& labels);
		ExprId AddOperandList(const std::vector<ExprId> operands);

		ExprId Operand(uint32_t n, ExprId expr);

		BNLowLevelILInstruction operator[](size_t i) const;
		size_t GetIndexForInstruction(size_t i) const;
		size_t GetInstructionCount() const;

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

		size_t GetSSARegisterDefinition(uint32_t reg, size_t idx) const;
		size_t GetSSAFlagDefinition(uint32_t flag, size_t idx) const;
		size_t GetSSAMemoryDefinition(size_t idx) const;
		std::set<size_t> GetSSARegisterUses(uint32_t reg, size_t idx) const;
		std::set<size_t> GetSSAFlagUses(uint32_t flag, size_t idx) const;
		std::set<size_t> GetSSAMemoryUses(size_t idx) const;

		RegisterValue GetSSARegisterValue(uint32_t reg, size_t idx);
		RegisterValue GetSSAFlagValue(uint32_t flag, size_t idx);
		RegisterValue GetSSAStackContents(size_t memoryIndex, int64_t offset, size_t size);
	};

	class FunctionRecognizer
	{
		static bool RecognizeLowLevelILCallback(void* ctxt, BNBinaryView* data, BNFunction* func, BNLowLevelILFunction* il);

	public:
		FunctionRecognizer();

		static void RegisterGlobalRecognizer(FunctionRecognizer* recog);
		static void RegisterArchitectureFunctionRecognizer(Architecture* arch, FunctionRecognizer* recog);

		virtual bool RecognizeLowLevelIL(BinaryView* data, Function* func, LowLevelILFunction* il);
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

		bool AreUpdatesAvailable();

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
		Ref<Function> function;

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

		static void DefaultPluginCommandActionCallback(void* ctxt, BNBinaryView* view);
		static void AddressPluginCommandActionCallback(void* ctxt, BNBinaryView* view, uint64_t addr);
		static void RangePluginCommandActionCallback(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len);
		static void FunctionPluginCommandActionCallback(void* ctxt, BNBinaryView* view, BNFunction* func);

		static bool DefaultPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view);
		static bool AddressPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, uint64_t addr);
		static bool RangePluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len);
		static bool FunctionPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, BNFunction* func);

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

		static uint32_t GetIntegerReturnValueRegisterCallback(void* ctxt);
		static uint32_t GetHighIntegerReturnValueRegisterCallback(void* ctxt);
		static uint32_t GetFloatReturnValueRegisterCallback(void* ctxt);

	public:
		Ref<Architecture> GetArchitecture() const;
		std::string GetName() const;

		virtual std::vector<uint32_t> GetCallerSavedRegisters();

		virtual std::vector<uint32_t> GetIntegerArgumentRegisters();
		virtual std::vector<uint32_t> GetFloatArgumentRegisters();
		virtual bool AreArgumentRegistersSharedIndex();
		virtual bool IsStackReservedForArgumentRegisters();

		virtual uint32_t GetIntegerReturnValueRegister() = 0;
		virtual uint32_t GetHighIntegerReturnValueRegister();
		virtual uint32_t GetFloatReturnValueRegister();
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

		virtual uint32_t GetIntegerReturnValueRegister() override;
		virtual uint32_t GetHighIntegerReturnValueRegister() override;
		virtual uint32_t GetFloatReturnValueRegister() override;
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
	};

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
}
