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

	class TemporaryFile: public RefCountObject
	{
		BNTemporaryFile* m_file;

	public:
		TemporaryFile();
		TemporaryFile(const DataBuffer& contents);
		TemporaryFile(const std::string& contents);
		TemporaryFile(BNTemporaryFile* file);
		~TemporaryFile();

		bool IsValid() const { return m_file != nullptr; }
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

	class FileMetadata: public RefCountObject
	{
		BNFileMetadata* m_file;

	public:
		FileMetadata();
		FileMetadata(const std::string& filename);
		FileMetadata(BNFileMetadata* file);
		~FileMetadata();

		BNFileMetadata* GetFileObject() const { return m_file; }

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

	class Architecture;
	class Function;
	class BasicBlock;

	class Symbol: public RefCountObject
	{
		BNSymbol* m_sym;

	public:
		Symbol(BNSymbolType type, const std::string& shortName, const std::string& fullName,
		       const std::string& rawName, uint64_t addr);
		Symbol(BNSymbolType type, const std::string& name, uint64_t addr);
		Symbol(BNSymbol* sym);
		virtual ~Symbol();

		BNSymbol* GetSymbolObject() const { return m_sym; }

		BNSymbolType GetType() const;
		std::string GetShortName() const;
		std::string GetFullName() const;
		std::string GetRawName() const;
		uint64_t GetAddress() const;
		bool IsAutoDefined() const;
		void SetAutoDefined(bool val);
	};

	struct ReferenceSource
	{
		Ref<Function> func;
		Ref<Architecture> arch;
		uint64_t addr;
	};

	class BinaryView: public RefCountObject
	{
	protected:
		BNBinaryView* m_view;
		Ref<FileMetadata> m_file;

		BinaryView(const std::string& typeName, FileMetadata* file);

		virtual size_t PerformRead(void* dest, uint64_t offset, size_t len) { (void)dest; (void)offset; (void)len; return 0; }
		virtual size_t PerformWrite(uint64_t offset, const void* data, size_t len) { (void)offset; (void)data; (void)len; return 0; }
		virtual size_t PerformInsert(uint64_t offset, const void* data, size_t len) { (void)offset; (void)data; (void)len; return 0; }
		virtual size_t PerformRemove(uint64_t offset, uint64_t len) { (void)offset; (void)len; return 0; }

		virtual BNModificationStatus PerformGetModification(uint64_t offset) { (void)offset; return Original; }
		virtual bool PerformIsValidOffset(uint64_t offset);
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
		static size_t ReadCallback(void* ctxt, void* dest, uint64_t offset, size_t len);
		static size_t WriteCallback(void* ctxt, uint64_t offset, const void* src, size_t len);
		static size_t InsertCallback(void* ctxt, uint64_t offset, const void* src, size_t len);
		static size_t RemoveCallback(void* ctxt, uint64_t offset, uint64_t len);
		static BNModificationStatus GetModificationCallback(void* ctxt, uint64_t offset);
		static bool IsValidOffsetCallback(void* ctxt, uint64_t offset);
		static uint64_t GetStartCallback(void* ctxt);
		static uint64_t GetLengthCallback(void* ctxt);
		static uint64_t GetEntryPointCallback(void* ctxt);
		static bool IsExecutableCallback(void* ctxt);
		static BNEndianness GetDefaultEndiannessCallback(void* ctxt);
		static size_t GetAddressSizeCallback(void* ctxt);
		static bool SaveCallback(void* ctxt, BNFileAccessor* file);

	public:
		BinaryView(BNBinaryView* view);
		virtual ~BinaryView();

		FileMetadata* GetFile() const { return m_file; }
		BNBinaryView* GetViewObject() const { return m_view; }

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

		uint64_t GetStart() const;
		uint64_t GetEnd() const;
		uint64_t GetLength() const;
		uint64_t GetEntryPoint() const;

		Ref<Architecture> GetDefaultArchitecture() const;
		void SetDefaultArchitecture(Architecture* arch);

		BNEndianness GetDefaultEndianness() const;
		size_t GetAddressSize() const;

		bool IsExecutable() const;

		bool Save(FileAccessor* file);
		bool Save(const std::string& path);

		void RegisterNotification(BinaryDataNotification* notify);
		void UnregisterNotification(BinaryDataNotification* notify);

		void AddFunctionForAnalysis(Architecture* arch, uint64_t addr);
		void AddEntryPointForAnalysis(Architecture* arch, uint64_t start);
		void RemoveAnalysisFunction(Function* func);
		void CreateUserFunction(Architecture* arch, uint64_t start);
		void UpdateAnalysis();
		void AbortAnalysis();

		std::vector<Ref<Function>> GetAnalysisFunctionList();
		Ref<Function> GetAnalysisFunction(Architecture* arch, uint64_t addr);
		Ref<Function> GetRecentAnalysisFunctionForAddress(uint64_t addr);
		std::vector<Ref<Function>> GetAnalysisFunctionsForAddress(uint64_t addr);
		Ref<Function> GetAnalysisEntryPoint();

		Ref<BasicBlock> GetRecentBasicBlockForAddress(uint64_t addr);
		std::vector<Ref<BasicBlock>> GetBasicBlocksForAddress(uint64_t addr);

		std::vector<ReferenceSource> GetCodeReferences(uint64_t addr);

		Ref<Symbol> GetSymbolByAddress(uint64_t addr);
		Ref<Symbol> GetSymbolByRawName(const std::string& name);
		std::vector<Ref<Symbol>> GetSymbolsByName(const std::string& name);
		std::vector<Ref<Symbol>> GetSymbols();
		std::vector<Ref<Symbol>> GetSymbolsOfType(BNSymbolType type);

		void DefineAutoSymbol(Symbol* sym);
		void UndefineAutoSymbol(Symbol* sym);

		void DefineSymbol(Symbol* sym);
		void UndefineSymbol(Symbol* sym);

		void DefineUserSymbol(Symbol* sym);
		void UndefineUserSymbol(Symbol* sym);

		bool IsNeverBranchPatchAvailable(Architecture* arch, uint64_t addr);
		bool IsAlwaysBranchPatchAvailable(Architecture* arch, uint64_t addr);
		bool IsInvertBranchPatchAvailable(Architecture* arch, uint64_t addr);
		bool IsSkipAndReturnZeroPatchAvailable(Architecture* arch, uint64_t addr);
		bool IsSkipAndReturnValuePatchAvailable(Architecture* arch, uint64_t addr);

		bool ConvertToNop(Architecture* arch, uint64_t addr);
		bool AlwaysBranch(Architecture* arch, uint64_t addr);
		bool InvertBranch(Architecture* arch, uint64_t addr);
		bool SkipAndReturnValue(Architecture* arch, uint64_t addr, uint64_t value);
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

	class Architecture;

	class BinaryViewType: public RefCountObject
	{
	protected:
		BNBinaryViewType* m_type;
		std::string m_nameForRegister, m_longNameForRegister;

		static BNBinaryView* CreateCallback(void* ctxt, BNBinaryView* data);
		static bool IsValidCallback(void* ctxt, BNBinaryView* data);

		BinaryViewType(BNBinaryViewType* type);

	public:
		BinaryViewType(const std::string& name, const std::string& longName);
		virtual ~BinaryViewType() {}

		static void Register(BinaryViewType* type);
		static Ref<BinaryViewType> GetByName(const std::string& name);
		static std::vector<Ref<BinaryViewType>> GetViewTypesForData(BinaryView* data);

		static void RegisterArchitecture(const std::string& name, uint32_t id, Architecture* arch);
		void RegisterArchitecture(uint32_t id, Architecture* arch);
		Ref<Architecture> GetArchitecture(uint32_t id);

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

	class Transform: public RefCountObject
	{
	protected:
		BNTransform* m_xform;
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

	class Architecture: public RefCountObject
	{
	protected:
		BNArchitecture* m_arch;
		std::string m_nameForRegister;

		Architecture(BNArchitecture* arch);

		static BNEndianness GetEndiannessCallback(void* ctxt);
		static size_t GetAddressSizeCallback(void* ctxt);
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
		static void FreeRegisterListCallback(void* ctxt, uint32_t* regs);
		static BNRegisterInfo GetRegisterInfoCallback(void* ctxt, uint32_t reg);
		static uint32_t GetStackPointerRegisterCallback(void* ctxt);

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

		BNArchitecture* GetArchitectureObject() const { return m_arch; }

		static void Register(Architecture* arch);
		static Ref<Architecture> GetByName(const std::string& name);
		static std::vector<Ref<Architecture>> GetList();

		std::string GetName() const;

		virtual BNEndianness GetEndianness() const = 0;
		virtual size_t GetAddressSize() const = 0;

		virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) = 0;
		virtual bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len,
		                                std::vector<InstructionTextToken>& result) = 0;

		virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il);
		virtual std::string GetRegisterName(uint32_t reg);
		virtual std::string GetFlagName(uint32_t flag);
		virtual std::string GetFlagWriteTypeName(uint32_t flags);
		virtual std::vector<uint32_t> GetFullWidthRegisters();
		virtual std::vector<uint32_t> GetAllRegisters();
		virtual BNRegisterInfo GetRegisterInfo(uint32_t reg);
		virtual uint32_t GetStackPointerRegister();
		std::vector<uint32_t> GetModifiedRegistersOnWrite(uint32_t reg);

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
	};

	class CoreArchitecture: public Architecture
	{
	public:
		CoreArchitecture(BNArchitecture* arch);
		virtual BNEndianness GetEndianness() const override;
		virtual size_t GetAddressSize() const override;
		virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override;
		virtual bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len,
		                                std::vector<InstructionTextToken>& result) override;
		virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override;
		virtual std::string GetRegisterName(uint32_t reg) override;
		virtual std::string GetFlagName(uint32_t flag) override;
		virtual std::string GetFlagWriteTypeName(uint32_t flags) override;
		virtual std::vector<uint32_t> GetFullWidthRegisters() override;
		virtual std::vector<uint32_t> GetAllRegisters() override;
		virtual BNRegisterInfo GetRegisterInfo(uint32_t reg) override;
		virtual uint32_t GetStackPointerRegister() override;

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

	class Function;

	struct BasicBlockEdge
	{
		BNBranchType type;
		uint64_t target;
		Ref<Architecture> arch;
	};

	class BasicBlock: public RefCountObject
	{
		BNBasicBlock* m_block;

	public:
		BasicBlock(BNBasicBlock* block);
		~BasicBlock();

		Ref<Function> GetFunction() const;
		Ref<Architecture> GetArchitecture() const;

		uint64_t GetStart() const;
		uint64_t GetEnd() const;
		uint64_t GetLength() const;

		std::vector<BasicBlockEdge> GetOutgoingEdges() const;

		void MarkRecentUse();
	};

	class FunctionGraph;

	class Function: public RefCountObject
	{
		BNFunction* m_func;

	public:
		Function(BNFunction* func);
		~Function();

		BNFunction* GetFunctionObject() const { return m_func; }

		Ref<Architecture> GetArchitecture() const;
		uint64_t GetStart() const;
		Ref<Symbol> GetSymbol() const;

		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;
		void MarkRecentUse();

		std::string GetCommentForAddress(uint64_t addr) const;
		std::vector<uint64_t> GetCommentedAddresses() const;
		void SetCommentForAddress(uint64_t addr, const std::string& comment);

		Ref<LowLevelILFunction> GetLowLevelIL() const;
		std::vector<Ref<BasicBlock>> GetLowLevelILBasicBlocks() const;

		Ref<FunctionGraph> CreateFunctionGraph();
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

	class FunctionGraphBlock: public RefCountObject
	{
		BNFunctionGraphBlock* m_block;

	public:
		FunctionGraphBlock(BNFunctionGraphBlock* block);
		~FunctionGraphBlock();

		BNFunctionGraphBlock* GetBlockObject() const { return m_block; }

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

	class LowLevelILFunction: public RefCountObject
	{
		BNLowLevelILFunction* m_func;

	public:
		LowLevelILFunction();
		LowLevelILFunction(BNLowLevelILFunction* func);
		~LowLevelILFunction();

		BNLowLevelILFunction* GetFunctionObject() const { return m_func; }

		uint64_t GetCurrentAddress() const;
		void SetCurrentAddress(uint64_t addr);

		size_t AddExpr(BNLowLevelILOperation operation, size_t size, uint32_t flags,
		               uint64_t a = 0, uint64_t b = 0, uint64_t c = 0, uint64_t d = 0);
		size_t AddInstruction(size_t expr);

		size_t Nop();
		size_t SetRegister(size_t size, uint32_t reg, uint64_t val);
		size_t SetRegisterSplit(size_t size, uint32_t high, uint32_t low, uint64_t val);
		size_t SetFlag(uint32_t flag, uint64_t val);
		size_t Load(size_t size, uint64_t addr);
		size_t Store(size_t size, uint64_t addr, uint64_t val);
		size_t Push(size_t size, uint64_t val);
		size_t Pop(size_t size);
		size_t Register(size_t size, uint32_t reg);
		size_t Const(size_t size, uint64_t val);
		size_t Flag(uint32_t reg);
		size_t Add(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t AddCarry(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t Sub(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t SubBorrow(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t And(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t Or(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t Xor(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t ShiftLeft(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t LogicalShiftRight(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t ArithShiftRight(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t RotateLeft(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t RotateLeftCarry(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t RotateRight(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t RotateRightCarry(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t Mult(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t MultDoublePrecUnsigned(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t MultDoublePrecSigned(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t DivUnsigned(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t DivDoublePrecUnsigned(size_t size, uint64_t high, uint64_t low, uint64_t div, uint32_t flags = 0);
		size_t DivSigned(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t DivDoublePrecSigned(size_t size, uint64_t high, uint64_t low, uint64_t div, uint32_t flags = 0);
		size_t ModUnsigned(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t ModDoublePrecUnsigned(size_t size, uint64_t high, uint64_t low, uint64_t div, uint32_t flags = 0);
		size_t ModSigned(size_t size, uint64_t a, uint64_t b, uint32_t flags = 0);
		size_t ModDoublePrecSigned(size_t size, uint64_t high, uint64_t low, uint64_t div, uint32_t flags = 0);
		size_t Neg(size_t size, uint64_t a, uint32_t flags = 0);
		size_t Not(size_t size, uint64_t a, uint32_t flags = 0);
		size_t SignExtend(size_t size, uint64_t a);
		size_t ZeroExtend(size_t size, uint64_t a);
		size_t Jump(uint64_t dest);
		size_t Call(uint64_t dest);
		size_t Return(size_t dest);
		size_t FlagCondition(BNLowLevelILFlagCondition cond);
		size_t CompareEqual(size_t size, uint64_t a, uint64_t b);
		size_t CompareNotEqual(size_t size, uint64_t a, uint64_t b);
		size_t CompareSignedLessThan(size_t size, uint64_t a, uint64_t b);
		size_t CompareUnsignedLessThan(size_t size, uint64_t a, uint64_t b);
		size_t CompareSignedLessEqual(size_t size, uint64_t a, uint64_t b);
		size_t CompareUnsignedLessEqual(size_t size, uint64_t a, uint64_t b);
		size_t CompareSignedGreaterEqual(size_t size, uint64_t a, uint64_t b);
		size_t CompareUnsignedGreaterEqual(size_t size, uint64_t a, uint64_t b);
		size_t CompareSignedGreaterThan(size_t size, uint64_t a, uint64_t b);
		size_t CompareUnsignedGreaterThan(size_t size, uint64_t a, uint64_t b);
		size_t SystemCall();
		size_t Breakpoint();
		size_t Undefined();
		size_t Unimplemented();
		size_t UnimplementedMemoryRef(size_t size, uint64_t addr);

		size_t Goto(BNLowLevelILLabel& label);
		size_t If(uint64_t operand, BNLowLevelILLabel& t, BNLowLevelILLabel& f);
		void MarkLabel(BNLowLevelILLabel& label);

		BNLowLevelILInstruction operator[](size_t i) const;
		size_t GetIndexForInstruction(size_t i) const;
		size_t GetInstructionCount() const;

		void AddLabelForAddress(Architecture* arch, uint64_t addr);
		BNLowLevelILLabel* GetLabelForAddress(Architecture* arch, uint64_t addr);

		void Finalize();
	};
}
