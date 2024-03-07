#pragma once

#include <exception>
#include <vector>
#include <string.h>

#include "binaryninjaapi.h"
#include "machoview.h"

namespace BinaryNinja
{
	struct fat_header
	{
		uint32_t magic;
		uint32_t nfat_arch;
	};

	struct fat_arch
	{
		cpu_type_t cputype;
		cpu_subtype_t cpusubtype;
		uint32_t offset;
		uint32_t size;
		uint32_t align;
	};

	struct fat_arch_64
	{
		cpu_type_t cputype;
		cpu_subtype_t cpusubtype;
		uint64_t offset;
		uint64_t size;
		uint32_t align;
		uint32_t reserved;
	};

	class FatMachoViewType: public BinaryViewType
	{
		cpu_type_t m_cputype;
		cpu_subtype_t m_cpusubtype;

	public:
		FatMachoViewType(const std::string& name, const std::string& long_name, cpu_type_t cputype, cpu_subtype_t cpusubtype);
		virtual Ref<BinaryView> Create(BinaryView* data) override;
		virtual bool IsTypeValidForData(BinaryView* data) override;
		virtual bool IsDeprecated() override { return true; }
	};

	void InitFatMachoViewType();
}
