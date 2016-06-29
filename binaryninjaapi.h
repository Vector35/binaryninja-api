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
#include <windows.h>
#endif
#include <stddef.h>
#include <string>
#include <vector>
#include <map>
#include <exception>
#include <functional>
#include <set>
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

		T* GetObject() { return m_object; }

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

		T* GetObject() { return m_object; }

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

	void Log(BNLogLevel level, const char* fmt, ...);
	void LogDebug(const char* fmt, ...);
	void LogInfo(const char* fmt, ...);
	void LogWarn(const char* fmt, ...);
	void LogError(const char* fmt, ...);
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
	                          std::string& output, std::string& errors);

	std::string GetVersionString();
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
		Ref<BinaryView> OpenExistingDatabase(const std::string& path);
		bool SaveAutoSnapshot(BinaryView* data);

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
		static void StringFoundCallback(void* ctxt, BNBinaryView* data, BNStringType type, uint64_t offset, size_t len);
		static void StringRemovedCallback(void* ctxt, BNBinaryView* data, BNStringType type, uint64_t offset, size_t len);

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
		virtual void OnStringFound(BinaryView* data, BNStringType type, uint64_t offset, size_t len) { (void)data; (void)type; (void)offset; (void)len; }
		virtual void OnStringRemoved(BinaryView* data, BNStringType type, uint64_t offset, size_t len) { (void)data; (void)type; (void)offset; (void)len; }
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

	class BinaryView: public CoreRefCountObject<BNBinaryView, BNNewViewReference, BNFreeBinaryView>
	{
	protected:
		Ref<FileMetadata> m_file;

		BinaryView(const std::string& typeName, FileMetadata* file);

		virtual size_t PerformRead(void* dest, uint64_t offset, size_t len) { (void)dest; (void)offset; (void)len; return 0; }
		virtual size_t PerformWrite(uint64_t offset, const void* data, size_t len) { (void)offset; (void)data; (void)len; return 0; }
		virtual size_t PerformInsert(uint64_t offset, const void* data, size_t len) { (void)offset; (void)data; (void)len; return 0; }
		virtual size_t PerformRemove(uint64_t offset, uint64_t len) { (void)offset; (void)len; return 0; }

		virtual BNModificationStatus PerformGetModification(uint64_t offset) { (void)offset; return Original; }
		virtual bool PerformIsValidOffset(uint64_t offset);
		virtual bool PerformIsOffsetReadable(uint64_t offset);
		virtual bool PerformIsOffsetWritable(uint64_t offset);
		virtual bool PerformIsOffsetExecutable(uint64_t offset);
		virtual uint64_t PerformGetNextValidOffset(uint64_t offset);
		virtual uint64_t PerformGetStart() const { return 0; }
		virtual uint64_t PerformGetLength() const { return 0; }
		virtual uint64_t PerformGetEntryPoint() const { return 0; }
		virtual bool PerformIsExecutable() const { return false; }
		virtual BNEndianness PerformGetDefaultEndianness() const;
		virtual size_t PerformGetAddressSize() const;

		virtual bool PerformSave(FileAccessor* file) { (void)file; return false; }

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
		std::string GetTypeName() const;

		bool IsModified() const;
		bool IsAnalysisChanged() const;
		bool IsBackedByDatabase() const;
		bool CreateDatabase(const std::string& path);
		bool SaveAutoSnapshot();

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
		void UpdateAnalysis();
		void AbortAnalysis();

		std::vector<Ref<Function>> GetAnalysisFunctionList();
		bool HasFunctions() const;
		Ref<Function> GetAnalysisFunction(Platform* platform, uint64_t addr);
		Ref<Function> GetRecentAnalysisFunctionForAddress(uint64_t addr);
		std::vector<Ref<Function>> GetAnalysisFunctionsForAddress(uint64_t addr);
		Ref<Function> GetAnalysisEntryPoint();

		Ref<BasicBlock> GetRecentBasicBlockForAddress(uint64_t addr);
		std::vector<Ref<BasicBlock>> GetBasicBlocksForAddress(uint64_t addr);

		std::vector<ReferenceSource> GetCodeReferences(uint64_t addr);
		std::vector<ReferenceSource> GetCodeReferences(uint64_t addr, uint64_t len);

		Ref<Symbol> GetSymbolByAddress(uint64_t addr);
		Ref<Symbol> GetSymbolByRawName(const std::string& name);
		std::vector<Ref<Symbol>> GetSymbolsByName(const std::string& name);
		std::vector<Ref<Symbol>> GetSymbols();
		std::vector<Ref<Symbol>> GetSymbols(uint64_t start, uint64_t len);
		std::vector<Ref<Symbol>> GetSymbolsOfType(BNSymbolType type);
		std::vector<Ref<Symbol>> GetSymbolsOfType(BNSymbolType type, uint64_t start, uint64_t len);

		void DefineAutoSymbol(Symbol* sym);
		void UndefineAutoSymbol(Symbol* sym);

		void DefineUserSymbol(Symbol* sym);
		void UndefineUserSymbol(Symbol* sym);

		void DefineImportedFunction(Symbol* importAddressSym, Function* func);

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

		static void RegisterArchitecture(const std::string& name, uint32_t id, Architecture* arch);
		void RegisterArchitecture(uint32_t id, Architecture* arch);
		Ref<Architecture> GetArchitecture(uint32_t id);

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

	struct InstructionTextToken
	{
		BNInstructionTextTokenType type;
		std::string text;
		uint64_t value;

		InstructionTextToken();
		InstructionTextToken(BNInstructionTextTokenType type, const std::string& text, uint64_t value = 0);
	};

	class LowLevelILFunction;
	class FunctionRecognizer;
	class CallingConvention;

	typedef size_t ExprId;

	class Architecture: public StaticCoreRefCountObject<BNArchitecture>
	{
	protected:
		std::string m_nameForRegister;

		Architecture(BNArchitecture* arch);

		static void InitCallback(void* ctxt, BNArchitecture* obj);
		static BNEndianness GetEndiannessCallback(void* ctxt);
		static size_t GetAddressSizeCallback(void* ctxt);
		static size_t GetDefaultIntegerSizeCallback(void* ctxt);
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

		virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) = 0;
		virtual bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len,
		                                std::vector<InstructionTextToken>& result) = 0;

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

		virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);
		virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);
		virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);
		virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);
		virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		virtual bool ConvertToNop(uint8_t* data, uint64_t addr, size_t len);
		virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len);
		virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len);
		virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value);

		void RegisterFunctionRecognizer(FunctionRecognizer* recog);

		bool IsBinaryViewTypeConstantDefined(const std::string& type, const std::string& name);
		uint64_t GetBinaryViewTypeConstant(const std::string& type, const std::string& name,
		                                   uint64_t defaultValue = 0);
		void SetBinaryViewTypeConstant(const std::string& type, const std::string& name, uint64_t value);

		bool ParseTypesFromSource(const std::string& source, const std::string& fileName,
		                          std::map<std::string, Ref<Type>>& types, std::map<std::string, Ref<Type>>& variables,
		                          std::map<std::string, Ref<Type>>& functions, std::string& errors,
		                          const std::vector<std::string>& includeDirs = std::vector<std::string>());
		bool ParseTypesFromSourceFile(const std::string& fileName, std::map<std::string, Ref<Type>>& types,
		                              std::map<std::string, Ref<Type>>& variables,
		                              std::map<std::string, Ref<Type>>& functions, std::string& errors,
		                              const std::vector<std::string>& includeDirs = std::vector<std::string>());

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
	class Enumeration;

	struct NameAndType
	{
		std::string name;
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
		bool IsFloat() const;
		Ref<Type> GetChildType() const;
		Ref<CallingConvention> GetCallingConvention() const;
		std::vector<NameAndType> GetParameters() const;
		bool HasVariableArguments() const;
		bool CanReturn() const;
		Ref<Structure> GetStructure() const;
		Ref<Enumeration> GetEnumeration() const;
		uint64_t GetElementCount() const;

		std::string GetString() const;
		std::string GetStringBeforeName() const;
		std::string GetStringAfterName() const;

		Ref<Type> Duplicate() const;

		static Ref<Type> VoidType();
		static Ref<Type> BoolType();
		static Ref<Type> IntegerType(size_t width, bool sign);
		static Ref<Type> FloatType(size_t width);
		static Ref<Type> StructureType(Structure* strct);
		static Ref<Type> EnumerationType(Architecture* arch, Enumeration* enm, size_t width = 0);
		static Ref<Type> PointerType(Architecture* arch, Type* type, bool cnst = false);
		static Ref<Type> ArrayType(Type* type, uint64_t elem);
		static Ref<Type> FunctionType(Type* returnValue, CallingConvention* callingConvention,
		                              const std::vector<NameAndType>& params, bool varArg = false);
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
		Structure(BNStructure* s);

		std::string GetName() const;
		void SetName(const std::string& name);
		std::vector<StructureMember> GetMembers() const;
		uint64_t GetWidth() const;
		size_t GetAlignment() const;
		bool IsPacked() const;
		void SetPacked(bool packed);
		bool IsUnion() const;
		void SetUnion(bool u);

		void AddMember(Type* type, const std::string& name);
		void AddMemberAtOffset(Type* type, const std::string& name, uint64_t offset);
		void RemoveMember(size_t idx);
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

		std::string GetName() const;
		void SetName(const std::string& name);

		std::vector<EnumerationMember> GetMembers() const;

		void AddMember(const std::string& name);
		void AddMemberWithValue(const std::string& name, uint64_t value);
	};

	class Function;

	struct BasicBlockEdge
	{
		BNBranchType type;
		uint64_t target;
		Ref<Architecture> arch;
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

		std::vector<BasicBlockEdge> GetOutgoingEdges() const;
		bool HasUndeterminedOutgoingEdges() const;

		void MarkRecentUse();

		std::vector<std::vector<InstructionTextToken>> GetAnnotations();
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
	};

	class FunctionGraph;

	class Function: public CoreRefCountObject<BNFunction, BNNewFunctionReference, BNFreeFunction>
	{
	public:
		Function(BNFunction* func);

		Ref<Architecture> GetArchitecture() const;
		Ref<Platform> GetPlatform() const;
		uint64_t GetStart() const;
		Ref<Symbol> GetSymbol() const;
		bool WasAutomaticallyDiscovered() const;
		bool CanReturn() const;
		bool HasExplicitlyDefinedType() const;

		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;
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

		Ref<LowLevelILFunction> GetLiftedIL() const;
		size_t GetLiftedILForInstruction(Architecture* arch, uint64_t addr);
		std::set<size_t> GetLiftedILFlagUsesForDefinition(size_t i, uint32_t flag);
		std::set<size_t> GetLiftedILFlagDefinitionsForUse(size_t i, uint32_t flag);
		std::set<uint32_t> GetFlagsReadByLiftedILInstruction(size_t i);
		std::set<uint32_t> GetFlagsWrittenByLiftedILInstruction(size_t i);

		Ref<Type> GetType() const;
		void ApplyImportedTypes(Symbol* sym);
		void ApplyAutoDiscoveredType(Type* type);

		Ref<FunctionGraph> CreateFunctionGraph();

		std::map<int64_t, StackVariable> GetStackLayout();
		void CreateAutoStackVariable(int64_t offset, Type* type, const std::string& name);
		void CreateUserStackVariable(int64_t offset, Type* type, const std::string& name);
		void DeleteAutoStackVariable(int64_t offset);
		void DeleteUserStackVariable(int64_t offset);
		bool GetStackVariableAtFrameOffset(int64_t offset, StackVariable& var);

		void SetAutoIndirectBranches(Architecture* sourceArch, uint64_t source, const std::vector<ArchAndAddr>& branches);
		void SetUserIndirectBranches(Architecture* sourceArch, uint64_t source, const std::vector<ArchAndAddr>& branches);

		std::vector<IndirectBranchInfo> GetIndirectBranches();
		std::vector<IndirectBranchInfo> GetIndirectBranchesAt(Architecture* arch, uint64_t addr);

		std::vector<std::vector<InstructionTextToken>> GetBlockAnnotations(Architecture* arch, uint64_t addr);
	};

	struct FunctionGraphTextLine
	{
		uint64_t addr;
		std::vector<InstructionTextToken> tokens;
	};

	struct FunctionGraphEdge
	{
		BNBranchType type;
		uint64_t target;
		Ref<Architecture> arch;
		std::vector<BNPoint> points;
	};

	class FunctionGraphBlock: public CoreRefCountObject<BNFunctionGraphBlock,
		BNNewFunctionGraphBlockReference, BNFreeFunctionGraphBlock>
	{
	public:
		FunctionGraphBlock(BNFunctionGraphBlock* block);

		Ref<Architecture> GetArchitecture() const;
		uint64_t GetStart() const;
		uint64_t GetEnd() const;
		int GetX() const;
		int GetY() const;
		int GetWidth() const;
		int GetHeight() const;

		std::vector<FunctionGraphTextLine> GetLines() const;
		std::vector<FunctionGraphEdge> GetOutgoingEdges() const;
	};

	class FunctionGraph: public RefCountObject
	{
		BNFunctionGraph* m_graph;
		std::function<void()> m_completeFunc;

		static void CompleteCallback(void* ctxt);

	public:
		FunctionGraph(BNFunctionGraph* graph);
		~FunctionGraph();

		BNFunctionGraph* GetGraphObject() const { return m_graph; }

		Ref<Function> GetFunction() const;

		int GetHorizontalBlockMargin() const;
		int GetVerticalBlockMargin() const;
		void SetBlockMargins(int horiz, int vert);

		size_t GetMaximumSymbolWidth() const;
		void SetMaximumSymbolWidth(size_t width);

		void StartLayout(BNFunctionGraphType = NormalFunctionGraph);
		bool IsLayoutComplete();
		void OnComplete(const std::function<void()>& func);
		void Abort();

		std::vector<Ref<FunctionGraphBlock>> GetBlocks() const;

		int GetWidth() const;
		int GetHeight() const;
		std::vector<Ref<FunctionGraphBlock>> GetBlocksInRegion(int left, int top, int right, int bottom);

		bool IsOptionSet(BNFunctionGraphOption option) const;
		void SetOption(BNFunctionGraphOption option, bool state = true);
	};

	struct LowLevelILLabel: public BNLowLevelILLabel
	{
		LowLevelILLabel();
	};

	class LowLevelILFunction: public CoreRefCountObject<BNLowLevelILFunction,
		BNNewLowLevelILFunctionReference, BNFreeLowLevelILFunction>
	{
	public:
		LowLevelILFunction(Architecture* arch);
		LowLevelILFunction(BNLowLevelILFunction* func);

		uint64_t GetCurrentAddress() const;
		void SetCurrentAddress(uint64_t addr);

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

		void Finalize(Function* func = nullptr);

		bool GetExprText(Architecture* arch, ExprId expr, std::vector<InstructionTextToken>& tokens);
		bool GetInstructionText(Function* func, Architecture* arch, size_t i,
			std::vector<InstructionTextToken>& tokens);

		uint32_t GetTemporaryRegisterCount();
		uint32_t GetTemporaryFlagCount();

		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;
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
	};
}
