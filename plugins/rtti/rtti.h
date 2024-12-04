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

	enum class RTTIProcessorType
	{
		Microsoft = 0,
		Itanium = 1,
	};

	// TODO: This needs to have some flags. Virtual, pure iirc.
	struct ClassInfo
	{
		RTTIProcessorType processor;
		std::string className;
		std::optional<std::string> baseClassName;
		std::optional<uint64_t> classOffset;
		std::optional<VirtualFunctionTableInfo> vft;
		std::optional<VirtualFunctionTableInfo> baseVft;

		Ref<Metadata> SerializedMetadata();

		static ClassInfo DeserializedMetadata(const Ref<Metadata> &metadata);
	};

	class RTTIProcessor
	{
	protected:
		Ref<BinaryView> m_view;
		Ref<Logger> m_logger;

		std::map<uint64_t, ClassInfo> m_classInfo;
		std::map<uint64_t, ClassInfo> m_unhandledClassInfo;

		virtual std::optional<ClassInfo> ProcessRTTI(uint64_t objectAddr) = 0;

		virtual std::optional<VirtualFunctionTableInfo> ProcessVFT(uint64_t vftAddr, ClassInfo &classInfo) = 0;
	public:
		virtual ~RTTIProcessor() = default;

		void DeserializedMetadata(RTTIProcessorType type, const Ref<Metadata> &metadata);

		Ref<Metadata> SerializedMetadata();

		virtual void ProcessRTTI() = 0;

		virtual void ProcessVFT() = 0;
	};
}
