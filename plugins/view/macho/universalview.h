#pragma once

#include <exception>
#include <vector>
#include <string.h>

#include "binaryninjaapi.h"
#include "fatmachoview.h"
#include "machoview.h"


namespace BinaryNinja
{
	void InitUniversalViewType();

	class UniversalViewType: public BinaryViewType
	{
	public:
		static const std::map<std::pair<cpu_type_t, cpu_subtype_t>, std::string>& GetArchitectures();
		static std::string ArchitectureToString(cpu_type_t cpuType, cpu_subtype_t cpuSubType, bool& is64Bit);

		UniversalViewType(): BinaryViewType("Universal", "Universal") { }
		virtual Ref<BinaryView> Create(BinaryView* data) override;
		virtual bool IsTypeValidForData(BinaryView* data) override;
		virtual bool ParseHeaders(BinaryView* data, FatHeader& fatHeader, std::vector<FatArch64>& fatArchEntries, bool& isFat64, std::string& errorMsg);
		virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override;
	};

	class UniversalView: public BinaryView
	{
	public:
		UniversalView(BinaryView* data, bool parseOnly = false);
		virtual ~UniversalView();

		virtual bool Init() override;
		virtual BNEndianness PerformGetDefaultEndianness() const override { return BigEndian; }
		virtual bool PerformIsExecutable() const override { return false; }
		virtual bool PerformIsRelocatable() const override { return false; };
	};
}
