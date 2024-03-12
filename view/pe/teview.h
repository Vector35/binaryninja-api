#pragma once

#include "binaryninjaapi.h"
#include "peview.h"

#ifdef WIN32
#pragma warning(disable: 4005)
#endif


// EFI_IMAGE_DATA_DIRECTORY
struct TEImageDataDirectory {
	uint32_t virtualAddress;
	uint32_t size;
};

#define EFI_TE_IMAGE_HEADER_SIZE 40
#define EFI_TE_SECTION_HEADER_SIZE 40

// EFI section header characteristics bit masks
#define EFI_IMAGE_SCN_MEM_EXECUTE 0x20000000
#define EFI_IMAGE_SCN_MEM_READ 0x40000000
#define EFI_IMAGE_SCN_MEM_WRITE 0x80000000

// EFI_TE_IMAGE_HEADER
struct TEImageHeader {
	uint16_t magic;
	uint16_t machine;
	uint8_t numberOfSections;
	uint8_t subsystem;
	uint16_t strippedSize;
	uint32_t addressOfEntrypoint;
	uint32_t baseOfCode;
	uint64_t imageBase;
	struct TEImageDataDirectory dataDirectory[2];
};

// EFI_IMAGE_SECTION_HEADER
struct TEImageSectionHeader {
	std::string name; // 8 bytes
	uint32_t virtualSize;
	uint32_t virtualAddress;
	uint32_t sizeOfRawData;
	uint32_t pointerToRawData;
	uint32_t pointerToRelocations;
	uint32_t pointerToLineNumbers;
	uint16_t numberOfRelocations;
	uint16_t numberOfLineNumbers;
	uint32_t characteristics;
};

namespace BinaryNinja
{
	class TEView: public BinaryView
	{
		bool m_parseOnly;
		std::vector<TEImageSectionHeader> m_sections;
		bool m_relocatable = false;
		Ref<Logger> m_logger;
		bool m_backedByDatabase;
		uint64_t m_imageBase;
		uint64_t m_headersOffset;
		Ref<Architecture> m_arch;
		uint64_t m_entryPoint;
		
	protected:
		virtual uint64_t PerformGetEntryPoint() const override;
		virtual bool PerformIsExecutable() const override { return true; }
		virtual BNEndianness PerformGetDefaultEndianness() const override { return LittleEndian; }
		virtual bool PerformIsRelocatable() const override { return m_relocatable; }
		virtual size_t PerformGetAddressSize() const override;

	public:
		TEView(BinaryView* data, bool parseOnly = false);
		virtual bool Init() override;

	private:
		void ReadTEImageHeader(BinaryReader& reader, struct TEImageHeader& imageHeader);
		void ReadTEImageSectionHeaders(BinaryReader& reader, uint32_t numSections);
		void HandleUserOverrides();
		void CreateSections();
		void AssignHeaderTypes();
	};

	class TEViewType: public BinaryViewType
	{
		Ref<Logger> m_logger;

	public:
		TEViewType();
		virtual Ref<BinaryView> Create(BinaryView* data) override;
		virtual Ref<BinaryView> Parse(BinaryView* data) override;
		virtual bool IsTypeValidForData(BinaryView* data) override;
		virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override;
	};

	void InitTEViewType();
}
