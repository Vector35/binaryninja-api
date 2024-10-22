#pragma once

#include <binaryninjaapi.h>
#include "MetadataSerializable.hpp"
#include "view/macho/machoview.h"
#include "sharedcachecore.h"

using namespace BinaryNinja;

namespace SharedCacheAPI {
	template<class T>
	class SCRefCountObject {
		void AddRefInternal() { m_refs.fetch_add(1); }

		void ReleaseInternal() {
			if (m_refs.fetch_sub(1) == 1)
				delete this;
		}

	public:
		std::atomic<int> m_refs;
		T *m_object;

		SCRefCountObject() : m_refs(0), m_object(nullptr) {}

		virtual ~SCRefCountObject() {}

		T *GetObject() const { return m_object; }

		static T *GetObject(SCRefCountObject *obj) {
			if (!obj)
				return nullptr;
			return obj->GetObject();
		}

		void AddRef() { AddRefInternal(); }

		void Release() { ReleaseInternal(); }

		void AddRefForRegistration() { AddRefInternal(); }
	};


	template<class T, T *(*AddObjectReference)(T *), void (*FreeObjectReference)(T *)>
	class SCCoreRefCountObject {
		void AddRefInternal() { m_refs.fetch_add(1); }

		void ReleaseInternal() {
			if (m_refs.fetch_sub(1) == 1) {
				if (!m_registeredRef)
					delete this;
			}
		}

	public:
		std::atomic<int> m_refs;
		bool m_registeredRef = false;
		T *m_object;

		SCCoreRefCountObject() : m_refs(0), m_object(nullptr) {}

		virtual ~SCCoreRefCountObject() {}

		T *GetObject() const { return m_object; }

		static T *GetObject(SCCoreRefCountObject *obj) {
			if (!obj)
				return nullptr;
			return obj->GetObject();
		}

		void AddRef() {
			if (m_object && (m_refs != 0))
				AddObjectReference(m_object);
			AddRefInternal();
		}

		void Release() {
			if (m_object)
				FreeObjectReference(m_object);
			ReleaseInternal();
		}

		void AddRefForRegistration() { m_registeredRef = true; }

		void ReleaseForRegistration() {
			m_object = nullptr;
			m_registeredRef = false;
			if (m_refs == 0)
				delete this;
		}
	};


	template<class T>
	class SCRef {
		T *m_obj;
#ifdef BN_REF_COUNT_DEBUG
		void* m_assignmentTrace = nullptr;
#endif

	public:
		SCRef<T>() : m_obj(NULL) {}

		SCRef<T>(T *obj) : m_obj(obj) {
			if (m_obj) {
				m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			}
		}

		SCRef<T>(const SCRef<T> &obj) : m_obj(obj.m_obj) {
			if (m_obj) {
				m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			}
		}

		SCRef<T>(SCRef<T> &&other) : m_obj(other.m_obj) {
			other.m_obj = 0;
#ifdef BN_REF_COUNT_DEBUG
			m_assignmentTrace = other.m_assignmentTrace;
#endif
		}

		~SCRef<T>() {
			if (m_obj) {
				m_obj->Release();
#ifdef BN_REF_COUNT_DEBUG
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
#endif
			}
		}

		SCRef<T> &operator=(const Ref<T> &obj) {
#ifdef BN_REF_COUNT_DEBUG
			if (m_obj)
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
			if (obj.m_obj)
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			T *oldObj = m_obj;
			m_obj = obj.m_obj;
			if (m_obj)
				m_obj->AddRef();
			if (oldObj)
				oldObj->Release();
			return *this;
		}

		SCRef<T> &operator=(SCRef<T> &&other) {
			if (m_obj) {
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

		SCRef<T> &operator=(T *obj) {
#ifdef BN_REF_COUNT_DEBUG
			if (m_obj)
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
			if (obj)
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			T *oldObj = m_obj;
			m_obj = obj;
			if (m_obj)
				m_obj->AddRef();
			if (oldObj)
				oldObj->Release();
			return *this;
		}

		operator T *() const {
			return m_obj;
		}

		T *operator->() const {
			return m_obj;
		}

		T &operator*() const {
			return *m_obj;
		}

		bool operator!() const {
			return m_obj == NULL;
		}

		bool operator==(const T *obj) const {
			return T::GetObject(m_obj) == T::GetObject(obj);
		}

		bool operator==(const SCRef<T> &obj) const {
			return T::GetObject(m_obj) == T::GetObject(obj.m_obj);
		}

		bool operator!=(const T *obj) const {
			return T::GetObject(m_obj) != T::GetObject(obj);
		}

		bool operator!=(const SCRef<T> &obj) const {
			return T::GetObject(m_obj) != T::GetObject(obj.m_obj);
		}

		bool operator<(const T *obj) const {
			return T::GetObject(m_obj) < T::GetObject(obj);
		}

		bool operator<(const SCRef<T> &obj) const {
			return T::GetObject(m_obj) < T::GetObject(obj.m_obj);
		}

		T *GetPtr() const {
			return m_obj;
		}
	};

	struct DSCMemoryRegion {
		uint64_t vmAddress;
		uint64_t size;
		std::string prettyName;
	};

	struct BackingCacheMapping {
		uint64_t vmAddress;
		uint64_t size;
		uint64_t fileOffset;
	};

	struct BackingCache {
		std::string path;
		bool isPrimary;
		std::vector<BackingCacheMapping> mappings;
	};

	struct DSCImageMemoryMapping {
		std::string filePath;
		std::string name;
		uint64_t vmAddress;
		uint64_t size;
		bool loaded;
		uint64_t rawViewOffset;
	};

	struct DSCImage {
		std::string name;
		uint64_t headerAddress;
		std::vector<DSCImageMemoryMapping> mappings;
	};

	struct DSCSymbol {
		uint64_t address;
		std::string name;
		std::string image;
	};

	using namespace BinaryNinja;
	struct SharedCacheMachOHeader : public MetadataSerializable {
		uint64_t textBase = 0;
		uint64_t loadCommandOffset = 0;
		mach_header_64 ident;
		std::string identifierPrefix;
		std::string installName;

		std::vector<std::pair<uint64_t, bool>> entryPoints;
		std::vector<uint64_t> m_entryPoints; //list of entrypoints

		symtab_command symtab;
		dysymtab_command dysymtab;
		dyld_info_command dyldInfo;
		routines_command_64 routines64;
		function_starts_command functionStarts;
		std::vector<section_64> moduleInitSections;
		linkedit_data_command exportTrie;
		linkedit_data_command chainedFixups {};

		uint64_t relocationBase;
		// Section and program headers, internally use 64-bit form as it is a superset of 32-bit
		std::vector<segment_command_64> segments; //only three types of sections __TEXT, __DATA, __IMPORT
		segment_command_64 linkeditSegment;
		std::vector<section_64> sections;
		std::vector<std::string> sectionNames;

		std::vector<section_64> symbolStubSections;
		std::vector<section_64> symbolPointerSections;

		std::vector<std::string> dylibs;

		build_version_command buildVersion;
		std::vector<build_tool_version> buildToolVersions;

		std::string exportTriePath;

		bool dysymPresent = false;
		bool dyldInfoPresent = false;
		bool exportTriePresent = false;
		bool chainedFixupsPresent = false;
		bool routinesPresent = false;
		bool functionStartsPresent = false;
		bool relocatable = false;
		void Serialize(const std::string& name, mach_header_64 b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			bArr.PushBack(b.magic, m_activeContext.allocator);
			bArr.PushBack(b.cputype, m_activeContext.allocator);
			bArr.PushBack(b.cpusubtype, m_activeContext.allocator);
			bArr.PushBack(b.filetype, m_activeContext.allocator);
			bArr.PushBack(b.ncmds, m_activeContext.allocator);
			bArr.PushBack(b.sizeofcmds, m_activeContext.allocator);
			bArr.PushBack(b.flags, m_activeContext.allocator);
			bArr.PushBack(b.reserved, m_activeContext.allocator);
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, mach_header_64& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			b.magic = bArr[0].GetInt64();
			b.cputype = bArr[1].GetInt64();
			b.cpusubtype = bArr[2].GetInt64();
			b.filetype = bArr[3].GetInt64();
			b.ncmds = bArr[4].GetInt64();
			b.sizeofcmds = bArr[5].GetInt64();
			b.flags = bArr[6].GetInt64();
			b.reserved = bArr[7].GetInt64();
		}

		void Serialize(const std::string& name, symtab_command b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			bArr.PushBack(b.cmd, m_activeContext.allocator);
			bArr.PushBack(b.cmdsize, m_activeContext.allocator);
			bArr.PushBack(b.symoff, m_activeContext.allocator);
			bArr.PushBack(b.nsyms, m_activeContext.allocator);
			bArr.PushBack(b.stroff, m_activeContext.allocator);
			bArr.PushBack(b.strsize, m_activeContext.allocator);
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, symtab_command& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			b.cmd = bArr[0].GetUint();
			b.cmdsize = bArr[1].GetUint();
			b.symoff = bArr[2].GetUint();
			b.nsyms = bArr[3].GetUint();
			b.stroff = bArr[4].GetUint();
			b.strsize = bArr[5].GetUint();
		}

		void Serialize(const std::string& name, dysymtab_command b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			bArr.PushBack(b.cmd, m_activeContext.allocator);
			bArr.PushBack(b.cmdsize, m_activeContext.allocator);
			bArr.PushBack(b.ilocalsym, m_activeContext.allocator);
			bArr.PushBack(b.nlocalsym, m_activeContext.allocator);
			bArr.PushBack(b.iextdefsym, m_activeContext.allocator);
			bArr.PushBack(b.nextdefsym, m_activeContext.allocator);
			bArr.PushBack(b.iundefsym, m_activeContext.allocator);
			bArr.PushBack(b.nundefsym, m_activeContext.allocator);
			bArr.PushBack(b.tocoff, m_activeContext.allocator);
			bArr.PushBack(b.ntoc, m_activeContext.allocator);
			bArr.PushBack(b.modtaboff, m_activeContext.allocator);
			bArr.PushBack(b.nmodtab, m_activeContext.allocator);
			bArr.PushBack(b.extrefsymoff, m_activeContext.allocator);
			bArr.PushBack(b.nextrefsyms, m_activeContext.allocator);
			bArr.PushBack(b.indirectsymoff, m_activeContext.allocator);
			bArr.PushBack(b.nindirectsyms, m_activeContext.allocator);
			bArr.PushBack(b.extreloff, m_activeContext.allocator);
			bArr.PushBack(b.nextrel, m_activeContext.allocator);
			bArr.PushBack(b.locreloff, m_activeContext.allocator);
			bArr.PushBack(b.nlocrel, m_activeContext.allocator);
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, dysymtab_command& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			b.cmd = bArr[0].GetUint();
			b.cmdsize = bArr[1].GetUint();
			b.ilocalsym = bArr[2].GetUint();
			b.nlocalsym = bArr[3].GetUint();
			b.iextdefsym = bArr[4].GetUint();
			b.nextdefsym = bArr[5].GetUint();
			b.iundefsym = bArr[6].GetUint();
			b.nundefsym = bArr[7].GetUint();
			b.tocoff = bArr[8].GetUint();
			b.ntoc = bArr[9].GetUint();
			b.modtaboff = bArr[10].GetUint();
			b.nmodtab = bArr[11].GetUint();
			b.extrefsymoff = bArr[12].GetUint();
			b.nextrefsyms = bArr[13].GetUint();
			b.indirectsymoff = bArr[14].GetUint();
			b.nindirectsyms = bArr[15].GetUint();
			b.extreloff = bArr[16].GetUint();
			b.nextrel = bArr[17].GetUint();
			b.locreloff = bArr[18].GetUint();
			b.nlocrel = bArr[19].GetUint();
		}

		void Serialize(const std::string& name, dyld_info_command b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			bArr.PushBack(b.cmd, m_activeContext.allocator);
			bArr.PushBack(b.cmdsize, m_activeContext.allocator);
			bArr.PushBack(b.rebase_off, m_activeContext.allocator);
			bArr.PushBack(b.rebase_size, m_activeContext.allocator);
			bArr.PushBack(b.bind_off, m_activeContext.allocator);
			bArr.PushBack(b.bind_size, m_activeContext.allocator);
			bArr.PushBack(b.weak_bind_off, m_activeContext.allocator);
			bArr.PushBack(b.weak_bind_size, m_activeContext.allocator);
			bArr.PushBack(b.lazy_bind_off, m_activeContext.allocator);
			bArr.PushBack(b.lazy_bind_size, m_activeContext.allocator);
			bArr.PushBack(b.export_off, m_activeContext.allocator);
			bArr.PushBack(b.export_size, m_activeContext.allocator);
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, dyld_info_command& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			b.cmd = bArr[0].GetUint();
			b.cmdsize = bArr[1].GetUint();
			b.rebase_off = bArr[2].GetUint();
			b.rebase_size = bArr[3].GetUint();
			b.bind_off = bArr[4].GetUint();
			b.bind_size = bArr[5].GetUint();
			b.weak_bind_off = bArr[6].GetUint();
			b.weak_bind_size = bArr[7].GetUint();
			b.lazy_bind_off = bArr[8].GetUint();
			b.lazy_bind_size = bArr[9].GetUint();
			b.export_off = bArr[10].GetUint();
			b.export_size = bArr[11].GetUint();
		}

		void Serialize(const std::string& name, routines_command_64 b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			bArr.PushBack(b.cmd, m_activeContext.allocator);
			bArr.PushBack(b.cmdsize, m_activeContext.allocator);
			bArr.PushBack(b.init_address, m_activeContext.allocator);
			bArr.PushBack(b.init_module, m_activeContext.allocator);
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, routines_command_64& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			b.cmd = bArr[0].GetUint();
			b.cmdsize = bArr[1].GetUint();
			b.init_address = bArr[2].GetUint();
			b.init_module = bArr[3].GetUint();
		}

		void Serialize(const std::string& name, function_starts_command b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			bArr.PushBack(b.cmd, m_activeContext.allocator);
			bArr.PushBack(b.cmdsize, m_activeContext.allocator);
			bArr.PushBack(b.funcoff, m_activeContext.allocator);
			bArr.PushBack(b.funcsize, m_activeContext.allocator);
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, function_starts_command& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			b.cmd = bArr[0].GetUint();
			b.cmdsize = bArr[1].GetUint();
			b.funcoff = bArr[2].GetUint();
			b.funcsize = bArr[3].GetUint();
		}

		void Serialize(const std::string& name, std::vector<section_64> b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			for (auto& s : b)
			{
				rapidjson::Value sArr(rapidjson::kArrayType);
				std::string sectNameStr;
				char sectName[16];
				memcpy(sectName, s.sectname, 16);
				sectName[15] = 0;
				sectNameStr = std::string(sectName);
				sArr.PushBack(rapidjson::Value(sectNameStr.c_str(), m_activeContext.allocator), m_activeContext.allocator);
				std::string segNameStr;
				char segName[16];
				memcpy(segName, s.segname, 16);
				segName[15] = 0;
				segNameStr = std::string(segName);
				sArr.PushBack(rapidjson::Value(segNameStr.c_str(), m_activeContext.allocator), m_activeContext.allocator);
				sArr.PushBack(s.addr, m_activeContext.allocator);
				sArr.PushBack(s.size, m_activeContext.allocator);
				sArr.PushBack(s.offset, m_activeContext.allocator);
				sArr.PushBack(s.align, m_activeContext.allocator);
				sArr.PushBack(s.reloff, m_activeContext.allocator);
				sArr.PushBack(s.nreloc, m_activeContext.allocator);
				sArr.PushBack(s.flags, m_activeContext.allocator);
				sArr.PushBack(s.reserved1, m_activeContext.allocator);
				sArr.PushBack(s.reserved2, m_activeContext.allocator);
				sArr.PushBack(s.reserved3, m_activeContext.allocator);
				bArr.PushBack(sArr, m_activeContext.allocator);
			}
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, std::vector<section_64>& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			for (auto& s : bArr)
			{
				section_64 sec;
				auto s2 = s.GetArray();
				std::string sectNameStr = s2[0].GetString();
				memcpy(sec.sectname, sectNameStr.c_str(), sectNameStr.size());
				std::string segNameStr = s2[1].GetString();
				memcpy(sec.segname, segNameStr.c_str(), segNameStr.size());
				sec.addr = s2[2].GetUint64();
				sec.size = s2[3].GetUint64();
				sec.offset = s2[4].GetUint();
				sec.align = s2[5].GetUint();
				sec.reloff = s2[6].GetUint();
				sec.nreloc = s2[7].GetUint();
				sec.flags = s2[8].GetUint();
				sec.reserved1 = s2[9].GetUint();
				sec.reserved2 = s2[10].GetUint();
				sec.reserved3 = s2[11].GetUint();
				b.push_back(sec);
			}
		}

		void Serialize(const std::string& name, linkedit_data_command b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			bArr.PushBack(b.cmd, m_activeContext.allocator);
			bArr.PushBack(b.cmdsize, m_activeContext.allocator);
			bArr.PushBack(b.dataoff, m_activeContext.allocator);
			bArr.PushBack(b.datasize, m_activeContext.allocator);
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, linkedit_data_command& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			b.cmd = bArr[0].GetUint();
			b.cmdsize = bArr[1].GetUint();
			b.dataoff = bArr[2].GetUint();
			b.datasize = bArr[3].GetUint();
		}

		void Serialize(const std::string& name, segment_command_64 b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			std::string segNameStr;
			char segName[16];
			memcpy(segName, b.segname, 16);
			segName[15] = 0;
			segNameStr = std::string(segName);
			bArr.PushBack(rapidjson::Value(segNameStr.c_str(), m_activeContext.allocator), m_activeContext.allocator);
			bArr.PushBack(b.vmaddr, m_activeContext.allocator);
			bArr.PushBack(b.vmsize, m_activeContext.allocator);
			bArr.PushBack(b.fileoff, m_activeContext.allocator);
			bArr.PushBack(b.filesize, m_activeContext.allocator);
			bArr.PushBack(b.maxprot, m_activeContext.allocator);
			bArr.PushBack(b.initprot, m_activeContext.allocator);
			bArr.PushBack(b.nsects, m_activeContext.allocator);
			bArr.PushBack(b.flags, m_activeContext.allocator);
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, segment_command_64& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			std::string segNameStr = bArr[0].GetString();
			memcpy(b.segname, segNameStr.c_str(), segNameStr.size());
			b.vmaddr = bArr[1].GetUint64();
			b.vmsize = bArr[2].GetUint64();
			b.fileoff = bArr[3].GetUint64();
			b.filesize = bArr[4].GetUint64();
			b.maxprot = bArr[5].GetUint();
			b.initprot = bArr[6].GetUint();
			b.nsects = bArr[7].GetUint();
			b.flags = bArr[8].GetUint();
		}

		void Serialize(const std::string& name, std::vector<segment_command_64> b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			for (auto& s : b)
			{
				rapidjson::Value sArr(rapidjson::kArrayType);
				std::string segNameStr;
				char segName[16];
				memcpy(segName, s.segname, 16);
				segName[15] = 0;
				segNameStr = std::string(segName);
				sArr.PushBack(rapidjson::Value(segNameStr.c_str(), m_activeContext.allocator), m_activeContext.allocator);
				sArr.PushBack(s.vmaddr, m_activeContext.allocator);
				sArr.PushBack(s.vmsize, m_activeContext.allocator);
				sArr.PushBack(s.fileoff, m_activeContext.allocator);
				sArr.PushBack(s.filesize, m_activeContext.allocator);
				sArr.PushBack(s.maxprot, m_activeContext.allocator);
				sArr.PushBack(s.initprot, m_activeContext.allocator);
				sArr.PushBack(s.nsects, m_activeContext.allocator);
				sArr.PushBack(s.flags, m_activeContext.allocator);
				bArr.PushBack(sArr, m_activeContext.allocator);
			}
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, std::vector<segment_command_64>& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			for (auto& s : bArr)
			{
				segment_command_64 sec;
				auto s2 = s.GetArray();
				std::string segNameStr = s2[0].GetString();
				memcpy(sec.segname, segNameStr.c_str(), segNameStr.size());
				sec.vmaddr = s2[1].GetUint64();
				sec.vmsize = s2[2].GetUint64();
				sec.fileoff = s2[3].GetUint64();
				sec.filesize = s2[4].GetUint64();
				sec.maxprot = s2[5].GetUint();
				sec.initprot = s2[6].GetUint();
				sec.nsects = s2[7].GetUint();
				sec.flags = s2[8].GetUint();
				b.push_back(sec);
			}
		}

		void Serialize(const std::string& name, build_version_command b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			bArr.PushBack(b.cmd, m_activeContext.allocator);
			bArr.PushBack(b.cmdsize, m_activeContext.allocator);
			bArr.PushBack(b.platform, m_activeContext.allocator);
			bArr.PushBack(b.minos, m_activeContext.allocator);
			bArr.PushBack(b.sdk, m_activeContext.allocator);
			bArr.PushBack(b.ntools, m_activeContext.allocator);
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, build_version_command& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			b.cmd = bArr[0].GetUint();
			b.cmdsize = bArr[1].GetUint();
			b.platform = bArr[2].GetUint();
			b.minos = bArr[3].GetUint();
			b.sdk = bArr[4].GetUint();
			b.ntools = bArr[5].GetUint();
		}

		void Serialize(const std::string& name, std::vector<build_tool_version> b)
		{
			S();
			rapidjson::Value key(name.c_str(), m_activeContext.allocator);
			rapidjson::Value bArr(rapidjson::kArrayType);
			for (auto& s : b)
			{
				rapidjson::Value sArr(rapidjson::kArrayType);
				sArr.PushBack(s.tool, m_activeContext.allocator);
				sArr.PushBack(s.version, m_activeContext.allocator);
				bArr.PushBack(sArr, m_activeContext.allocator);
			}
			m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
		}

		void Deserialize(const std::string& name, std::vector<build_tool_version>& b)
		{
			auto bArr = m_activeDeserContext.doc[name.c_str()].GetArray();
			for (auto& s : bArr)
			{
				build_tool_version sec;
				auto s2 = s.GetArray();
				sec.tool = s2[0].GetUint();
				sec.version = s2[1].GetUint();
				b.push_back(sec);
			}
		}

		void Store() override {
			MSS(textBase);
			MSS(loadCommandOffset);
			MSS_SUBCLASS(ident);
			MSS(identifierPrefix);
			MSS(installName);
			MSS(entryPoints);
			MSS(m_entryPoints);
			MSS_SUBCLASS(symtab);
			MSS_SUBCLASS(dysymtab);
			MSS_SUBCLASS(dyldInfo);
			// MSS_SUBCLASS(routines64);
			MSS_SUBCLASS(functionStarts);
			MSS_SUBCLASS(moduleInitSections);
			MSS_SUBCLASS(exportTrie);
			MSS_SUBCLASS(chainedFixups);
			MSS(relocationBase);
			MSS_SUBCLASS(segments);
			MSS_SUBCLASS(linkeditSegment);
			MSS_SUBCLASS(sections);
			MSS(sectionNames);
			MSS_SUBCLASS(symbolStubSections);
			MSS_SUBCLASS(symbolPointerSections);
			MSS(dylibs);
			MSS_SUBCLASS(buildVersion);
			MSS_SUBCLASS(buildToolVersions);
			MSS(exportTriePath);
			MSS(dysymPresent);
			MSS(dyldInfoPresent);
			MSS(exportTriePresent);
			MSS(chainedFixupsPresent);
			MSS(routinesPresent);
			MSS(functionStartsPresent);
			MSS(relocatable);
		}
		void Load() override {
			MSL(textBase);
			MSL(loadCommandOffset);
			MSL_SUBCLASS(ident);
			MSL(identifierPrefix);
			MSL(installName);
			MSL(entryPoints);
			MSL(m_entryPoints);
			MSL_SUBCLASS(symtab);
			MSL_SUBCLASS(dysymtab);
			MSL_SUBCLASS(dyldInfo);
			// MSL_SUBCLASS(routines64); // FIXME CRASH but also do we even use this?
			MSL_SUBCLASS(functionStarts);
			MSL_SUBCLASS(moduleInitSections);
			MSL_SUBCLASS(exportTrie);
			MSL_SUBCLASS(chainedFixups);
			MSL(relocationBase);
			MSL_SUBCLASS(segments);
			MSL_SUBCLASS(linkeditSegment);
			MSL_SUBCLASS(sections);
			MSL(sectionNames);
			MSL_SUBCLASS(symbolStubSections);
			MSL_SUBCLASS(symbolPointerSections);
			MSL(dylibs);
			MSL_SUBCLASS(buildVersion);
			MSL_SUBCLASS(buildToolVersions);
			MSL(exportTriePath);
			MSL(dysymPresent);
			MSL(dyldInfoPresent);
			MSL(exportTriePresent);
			MSL(chainedFixupsPresent);
			// MSL(routinesPresent);
			MSL(functionStartsPresent);
			MSL(relocatable);
		}
	};


	class SharedCache : public SCCoreRefCountObject<BNSharedCache, BNNewSharedCacheReference, BNFreeSharedCacheReference> {
	public:
		SharedCache(Ref<BinaryView> view);

		BNDSCViewState GetState();
		static BNDSCViewLoadProgress GetLoadProgress(Ref<BinaryView> view);
		static uint64_t FastGetBackingCacheCount(Ref<BinaryView> view);

		bool LoadImageWithInstallName(std::string installName);
		bool LoadSectionAtAddress(uint64_t addr);
		bool LoadImageContainingAddress(uint64_t addr);
		std::vector<std::string> GetAvailableImages();

		std::vector<DSCSymbol> LoadAllSymbolsAndWait();

		std::string GetNameForAddress(uint64_t address);
		std::string GetImageNameForAddress(uint64_t address);

		std::vector<BackingCache> GetBackingCaches();
		std::vector<DSCImage> GetImages();

		std::optional<SharedCacheMachOHeader> GetMachOHeaderForImage(std::string name);
		std::optional<SharedCacheMachOHeader> GetMachOHeaderForAddress(uint64_t address);

		std::vector<DSCMemoryRegion> GetLoadedMemoryRegions();

		void FindSymbolAtAddrAndApplyToAddr(uint64_t symbolLocation, uint64_t targetLocation, bool triggerReanalysis = true) const;
	};
}