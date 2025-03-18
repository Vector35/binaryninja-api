#pragma once

#include "binaryninjaapi.h"

constexpr const char *VIEW_METADATA_MSVC = "msvc";

namespace BinaryNinja {
	struct BaseClassArray
	{
		uint32_t length;
		std::vector<uint64_t> descriptors;

		BaseClassArray(BinaryView *view, uint64_t address, uint32_t length);
	};

	struct ClassHierarchyDescriptor
	{
		uint32_t signature;
		uint32_t attributes;
		uint32_t numBaseClasses;
		int32_t pBaseClassArray;

		ClassHierarchyDescriptor(BinaryView *view, uint64_t address);
	};

	struct BaseClassDescriptor
	{
		int32_t pTypeDescriptor;
		uint32_t numContainedBases;
		int32_t where_mdisp;
		int32_t where_pdisp;
		int32_t where_vdisp;
		uint32_t attributes;
		int32_t pClassHierarchyDescriptor;

		BaseClassDescriptor(BinaryView *view, uint64_t address);
	};

	struct TypeDescriptor
	{
		uint64_t pVFTable;
		uint64_t spare;
		std::string name;

		TypeDescriptor(BinaryView *view, uint64_t address);
	};

	struct CompleteObjectLocator
	{
		uint32_t signature;
		uint32_t offset;
		uint32_t cdOffset;
		int32_t pTypeDescriptor;
		int32_t pClassHierarchyDescriptor;
		// Only on 64 bit
		int32_t pSelf;

		CompleteObjectLocator(BinaryView *view, uint64_t address);
	};

	struct VirtualFunctionInfo
	{
		uint64_t funcAddr;

		Ref<Metadata> SerializedMetadata();

		static VirtualFunctionInfo DeserializedMetadata(const Ref<Metadata> &metadata);
	};

	struct VirtualFunctionTableInfo
	{
		uint64_t address;
		std::vector<VirtualFunctionInfo> virtualFunctions;

		Ref<Metadata> SerializedMetadata();

		static VirtualFunctionTableInfo DeserializedMetadata(const Ref<Metadata> &metadata);
	};

	struct ClassInfo
	{
		std::string className;
		std::optional<std::string> baseClassName;
		std::optional<uint64_t> classOffset;
		std::optional<VirtualFunctionTableInfo> vft;
		std::optional<VirtualFunctionTableInfo> baseVft;

		Ref<Metadata> SerializedMetadata();

		static ClassInfo DeserializedMetadata(const Ref<Metadata> &metadata);
	};

	class MicrosoftRTTIProcessor
	{
		Ref<BinaryView> m_view;
		Ref<Logger> m_logger;
		bool allowMangledClassNames;
		bool allowAnonymousClassNames;
		bool checkWritableRData;
		bool virtualFunctionTableSweep;

		std::map<uint64_t, ClassInfo> m_classInfo;

		std::set<uint64_t> m_visitedClassHierarchyDescAddrs;

		void DeserializedMetadata(const Ref<Metadata> &metadata);

		std::optional<std::string> DemangleName(const std::string &mangledName);

		std::optional<ClassInfo> ProcessRTTI(uint64_t coLocatorAddr);

		std::optional<VirtualFunctionTableInfo> ProcessVFT(uint64_t vftAddr, const ClassInfo &classInfo);

	public:
		MicrosoftRTTIProcessor(const Ref<BinaryView> &view, bool useMangled = true, bool checkRData = true, bool vftSweep = true, bool allowAnonymous = true);

		Ref<Metadata> SerializedMetadata();

		void ProcessRTTI();

		void ProcessVFT();
	};
}