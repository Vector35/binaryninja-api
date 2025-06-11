#pragma once

#include "binaryninjaapi.h"
#include "rtti.h"

namespace BinaryNinja::RTTI::Microsoft {
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

	class MicrosoftRTTIProcessor : public RTTIProcessor
	{
		bool allowMangledClassNames;
		bool allowAnonymousClassNames;
		bool checkWritableRData;
		bool virtualFunctionTableSweep;

		// This will process a CHD and store all `BaseClassInfo` in `classInfo`.
		std::vector<BaseClassInfo> ProcessClassHierarchyDescriptor(uint64_t address, CompleteObjectLocator &coLocator, const ClassInfo &classInfo);

		std::optional<ClassInfo> ProcessRTTI(uint64_t objectAddr) override;

		std::optional<VirtualFunctionTableInfo> ProcessVFT(uint64_t vftAddr, ClassInfo &classInfo, std::optional<BaseClassInfo> baseClassInfo) override;
	public:
		explicit MicrosoftRTTIProcessor(const Ref<BinaryView> &view, bool useMangled = true, bool checkRData = true, bool vftSweep = true, bool allowAnonymous = true);

		void ProcessRTTI() override;

		void ProcessVFT() override;
	};
}