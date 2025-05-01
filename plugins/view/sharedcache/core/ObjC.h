#pragma once

#include <binaryninjaapi.h>
#include <objectivec/objc.h>
#include "SharedCache.h"

struct ObjCOptimizationHeader
{
	uint32_t version;
	uint32_t flags;
	uint64_t headerInfoROCacheOffset;
	uint64_t headerInfoRWCacheOffset;
	uint64_t selectorHashTableCacheOffset;
	uint64_t classHashTableCacheOffset;
	uint64_t protocolHashTableCacheOffset;
	uint64_t relativeMethodSelectorBaseAddressOffset;
};

namespace DSCObjC {
	class SharedCacheObjCReader : public BinaryNinja::ObjCReader
	{
		VirtualMemoryReader m_reader;

	public:
		void Read(void* dest, size_t len) override;

		std::string ReadCString(size_t maxLength = -1) override;

		uint8_t Read8() override;

		uint16_t Read16() override;

		uint32_t Read32() override;

		uint64_t Read64() override;

		int8_t ReadS8() override;

		int16_t ReadS16() override;

		int32_t ReadS32() override;

		int64_t ReadS64() override;

		uint64_t ReadPointer() override;

		uint64_t GetOffset() const override;

		void Seek(uint64_t offset) override;

		void SeekRelative(int64_t offset) override;

		VirtualMemoryReader& GetVMReader();

		SharedCacheObjCReader(VirtualMemoryReader reader);
	};

	class SharedCacheObjCProcessor : public BinaryNinja::ObjCProcessor
	{
		std::optional<uint64_t> m_customRelativeMethodSelectorBase = std::nullopt;
		uint64_t m_imageAddress;

		std::shared_ptr<BinaryNinja::ObjCReader> GetReader() override;

		void GetRelativeMethod(BinaryNinja::ObjCReader* reader, BinaryNinja::method_t& meth) override;

		BinaryNinja::Ref<BinaryNinja::Symbol> GetSymbol(uint64_t address) override;

		BinaryNinja::Ref<BinaryNinja::Section> GetSectionWithName(const char *sectionName) override;

	public:
		SharedCacheObjCProcessor(BinaryNinja::BinaryView* data, bool isBackedByDatabase, uint64_t imageAddress);

		uint64_t GetObjCRelativeMethodBaseAddress(BinaryNinja::ObjCReader* reader) override;
	};
}  // namespace DSCObjC
