#pragma once

#include "binaryninjaapi.h"
#include "machoview.h"

namespace BinaryNinja
{
	void InitUniversalTransform();

	class UniversalTransform : public Transform
	{
	public:
		static const std::map<std::pair<cpu_type_t, cpu_subtype_t>, std::string>& GetArchitectures();
		static std::string ArchitectureToString(cpu_type_t cpuType, cpu_subtype_t cpuSubType, bool& is64Bit);
		static bool ParseHeaders(Ref<BinaryView> data, FatHeader& fatHeader, std::vector<FatArch64>& fatArchEntries, bool& isFat64, std::string& errorMsg);

		UniversalTransform();

		virtual bool Decode(const DataBuffer& input, DataBuffer& output, const std::map<std::string, DataBuffer>& params) override;
		virtual bool DecodeWithContext(Ref<TransformContext> context, const std::map<std::string, DataBuffer>& params) override;
		virtual bool Encode(const DataBuffer& input, DataBuffer& output, const std::map<std::string, DataBuffer>& params) override;
		virtual bool CanDecode(Ref<BinaryView> input) const override;
	};
}
