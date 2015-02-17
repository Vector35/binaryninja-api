#pragma once

#ifdef WIN32
#include <windows.h>
#endif
#include <stddef.h>
#include <string>
#include <vector>
#include <map>
#include <exception>
#include "binaryninjacore.h"

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
		size_t GetLength() const;

		void SetSize(size_t len);
		void Append(const void* data, size_t len);
		void Append(const DataBuffer& buf);
		void AppendByte(uint8_t val);

		DataBuffer GetSlice(size_t start, size_t len);

		uint8_t& operator[](size_t offset);
		const uint8_t& operator[](size_t offset) const;

		std::string ToEscapedString() const;
		static DataBuffer FromEscapedString(const std::string& src);
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

	class UndoAction
	{
	private:
		static void UndoCallback(void* ctxt);
		static void RedoCallback(void* ctxt);

	public:
		virtual ~UndoAction() {}

		void Add(BNFileMetadata* file);

		virtual void Undo() = 0;
		virtual void Redo() = 0;
	};

	class FileMetadata: public RefCountObject
	{
		BNFileMetadata* m_file;

	public:
		FileMetadata();
		FileMetadata(BNFileMetadata* file);
		~FileMetadata();

		BNFileMetadata* GetFileObject() const { return m_file; }

		void SetNavigationHandler(NavigationHandler* handler);

		bool IsModified() const;
		void MarkFileModified();
		void MarkFileSaved();

		void BeginUndoActions();
		void AddUndoAction(UndoAction* action);
		void CommitUndoActions();

		bool Undo();
		bool Redo();

		std::string GetCurrentView();
		uint64_t GetCurrentOffset();
		bool Navigate(const std::string& view, uint64_t offset);
	};

	class BinaryView;

	class BinaryDataNotification
	{
	private:
		BNBinaryDataNotification m_callbacks;

		static void DataWrittenCallback(void* ctxt, BNBinaryView* data, uint64_t offset, size_t len);
		static void DataInsertedCallback(void* ctxt, BNBinaryView* data, uint64_t offset, size_t len);
		static void DataRemovedCallback(void* ctxt, BNBinaryView* data, uint64_t offset, uint64_t len);

	public:
		BinaryDataNotification();
		virtual ~BinaryDataNotification() {}

		BNBinaryDataNotification* GetCallbacks() { return &m_callbacks; }

		virtual void OnBinaryDataWritten(BinaryView* view, uint64_t offset, size_t len) = 0;
		virtual void OnBinaryDataInserted(BinaryView* view, uint64_t offset, size_t len) = 0;
		virtual void OnBinaryDataRemoved(BinaryView* view, uint64_t offset, uint64_t len) = 0;
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

	class BinaryView: public RefCountObject
	{
	protected:
		BNBinaryView* m_view;
		Ref<FileMetadata> m_file;

		BinaryView(FileMetadata* file);

	private:
		static size_t ReadCallback(void* ctxt, void* dest, uint64_t offset, size_t len);
		static size_t WriteCallback(void* ctxt, uint64_t offset, const void* src, size_t len);
		static size_t InsertCallback(void* ctxt, uint64_t offset, const void* src, size_t len);
		static size_t RemoveCallback(void* ctxt, uint64_t offset, uint64_t len);
		static BNModificationStatus GetModificationCallback(void* ctxt, uint64_t offset);
		static uint64_t GetStartCallback(void* ctxt);
		static uint64_t GetLengthCallback(void* ctxt);
		static bool IsExecutableCallback(void* ctxt);
		static bool SaveCallback(void* ctxt, BNFileAccessor* file);

		virtual size_t PerformRead(void* dest, uint64_t offset, size_t len) { (void)dest; (void)offset; (void)len; return 0; }
		virtual size_t PerformWrite(uint64_t offset, const void* data, size_t len) { (void)offset; (void)data; (void)len; return 0; }
		virtual size_t PerformInsert(uint64_t offset, const void* data, size_t len) { (void)offset; (void)data; (void)len; return 0; }
		virtual size_t PerformRemove(uint64_t offset, uint64_t len) { (void)offset; (void)len; return 0; }

		virtual BNModificationStatus PerformGetModification(uint64_t offset) { (void)offset; return Original; }
		virtual uint64_t PerformGetStart() const { return 0; }
		virtual uint64_t PerformGetLength() const { return 0; }
		virtual bool PerformIsExecutable() const { return false; }

		virtual bool PerformSave(FileAccessor* file) { (void)file; return false; }

	public:
		BinaryView(BNBinaryView* view);
		virtual ~BinaryView();

		FileMetadata* GetFile() const { return m_file; }
		BNBinaryView* GetViewObject() const { return m_view; }

		bool IsModified() const;

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

		bool IsExecutable() const;

		bool Save(FileAccessor* file);
		bool Save(const std::string& path);

		void RegisterNotification(BinaryDataNotification* notify);
		void UnregisterNotification(BinaryDataNotification* notify);
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
		virtual ~BinaryViewType();

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
		void AddBranch(BNBranchType type, uint64_t target = 0);
	};

	class Architecture: public RefCountObject
	{
	protected:
		BNArchitecture* m_arch;
		std::string m_nameForRegister;

		Architecture(BNArchitecture* arch);

		static bool GetInstructionInfoCallback(void* ctxt, BNBinaryView* data, uint64_t addr, BNInstructionInfo* result);

	public:
		Architecture(const std::string& name);

		BNArchitecture* GetArchitectureObject() const { return m_arch; }

		static void Register(Architecture* arch);
		static Ref<Architecture> GetByName(const std::string& name);
		static std::vector<Ref<Architecture>> GetList();

		std::string GetName() const;

		virtual bool GetInstructionInfo(BinaryView* data, uint64_t addr, InstructionInfo& result) = 0;
	};

	class CoreArchitecture: public Architecture
	{
	public:
		CoreArchitecture(BNArchitecture* arch);
		virtual bool GetInstructionInfo(BinaryView* view, uint64_t addr, InstructionInfo& result) override;
	};
}
