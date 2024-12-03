#pragma once

#include "binaryninjaapi.h"

constexpr const char *VIEW_METADATA_RTTI = "rtti";
constexpr int RTTI_CONFIDENCE = 100;

namespace BinaryNinja::RTTI {
	std::optional<std::string> DemangleNameMS(BinaryView* view, bool allowMangled, const std::string &mangledName);

	std::optional<std::string> DemangleNameItanium(BinaryView* view, bool allowMangled, const std::string &mangledName);

	std::optional<std::string> DemangleNameLLVM(bool allowMangled, const std::string &mangledName);

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

	// TODO: This needs to have some flags. Virtual, pure iirc.
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
}