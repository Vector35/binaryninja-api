#pragma once

#include "binaryninjaapi.h"
#include "rtti.h"

namespace BinaryNinja::RTTI::Itanium {
	enum TypeInfoVariant
	{
		TIVFundamental,
		TIVArray,
		TIVFunction,
		TIVEnum,
		TIVClass,
		TIVSIClass,
		TIVVMIClass,
		TIVBasePointer,
		TIVPointer,
		TIVPointerToMember,
	};

	struct TypeInfo
	{
		// This might also be zero, and also this is at -1 offset.
		uint64_t base;
		std::string type_name;

		TypeInfo(BinaryView *view, uint64_t address);
	};

	struct FundamentalTypeInfo : TypeInfo {};

	struct ArrayTypeInfo : TypeInfo {};

	struct FunctionTypeInfo : TypeInfo {};

	struct EnumTypeInfo : TypeInfo {};

	struct ClassTypeInfo : TypeInfo
	{
		ClassTypeInfo(BinaryView *view, uint64_t uint64) : TypeInfo(view, uint64) {}
	};

	struct SIClassTypeInfo : ClassTypeInfo
	{
		uint64_t base_type;

		SIClassTypeInfo(BinaryView *view, uint64_t address);
	};

	enum OffsetFlagsMasks
	{
		virtual_mask = 0x1,
		public_mask = 0x2,
		offset_shift = 8
	};

	struct BaseClassTypeInfo
	{
		uint64_t base_type;
		uint64_t offset_flags;
		OffsetFlagsMasks offset_flags_masks;

		BaseClassTypeInfo(BinaryView *view, uint64_t address);
	};

	struct VMIClassTypeInfo : ClassTypeInfo
	{
		uint64_t flags;
		uint64_t base_count;
		std::vector<BaseClassTypeInfo> base_info;

		VMIClassTypeInfo(BinaryView *view, uint64_t address);
	};

	enum BasePointerMasks
	{
		// `pointee` type has const qualifier
		const_mask = 0x1,
		// `pointee` type has volatile qualifier
		volatile_mask = 0x2,
		// `pointee` type has restrict qualifier
		restrict_mask = 0x4,
		// `pointee` type is incomplete
		incomplete_mask = 0x8,
		// class containing `pointee` is incomplete (in pointer to member)
		incomplete_class_mask = 0x10,
		// `pointee` type is function type without the transaction-safe indication
		transaction_safe_mask = 0x20,
		// `pointee` type is function type without the exception specification
		noexcept_mask = 0x40
	};

	struct BasePointerTypeInfo : TypeInfo
	{
		uint64_t flags;
		uint64_t pointee;
		BasePointerMasks masks;

		BasePointerTypeInfo(BinaryView *view, uint64_t address);
	};

	struct PointerTypeInfo : BasePointerTypeInfo {};

	struct PointerToMemberTypeInfo : BasePointerTypeInfo
	{
		uint64_t context;

		PointerToMemberTypeInfo(BinaryView *view, uint64_t address);
	};

	class ItaniumRTTIProcessor
	{
		Ref<BinaryView> m_view;
		Ref<Logger> m_logger;
		bool allowMangledClassNames;
		bool checkWritableRData;
		bool virtualFunctionTableSweep;

		std::map<uint64_t, ClassInfo> m_classInfo;

		void DeserializedMetadata(const Ref<Metadata> &metadata);

		std::optional<VirtualFunctionTableInfo> ProcessVTT(uint64_t vttAddr, const ClassInfo &classInfo);

	public:
		ItaniumRTTIProcessor(const Ref<BinaryView> &view, bool useMangled = true, bool checkRData = true, bool vttSweep = true);

		Ref<Metadata> SerializedMetadata();

		void ProcessRTTI();

		std::optional<ClassInfo> ProcessRTTI(uint64_t objectAddr);

		void ProcessVTT();
	};
}