#pragma once

#include "binaryninjacore/binaryviewtype.h"
#include "refcount.hpp"

struct BNMetadata;

namespace BinaryNinja {
	class Architecture;
	class BinaryView;
	class Metadata;
	class Platform;
	class Settings;

	class BinaryViewType : public StaticCoreRefCountObject<BNBinaryViewType>
	{
		struct BinaryViewEvent
		{
			std::function<void(BinaryView*)> action;
		};

		struct PlatformRecognizerFunction
		{
			std::function<Ref<Platform>(BinaryView*, Metadata*)> action;
		};

	  protected:
		std::string m_nameForRegister, m_longNameForRegister;

		static BNBinaryView* CreateCallback(void* ctxt, BNBinaryView* data);
		static BNBinaryView* ParseCallback(void* ctxt, BNBinaryView* data);
		static bool IsValidCallback(void* ctxt, BNBinaryView* data);
		static bool IsDeprecatedCallback(void* ctxt);
		static BNSettings* GetSettingsCallback(void* ctxt, BNBinaryView* data);

		BinaryViewType(BNBinaryViewType* type);

	  public:
		BinaryViewType(const std::string& name, const std::string& longName);
		virtual ~BinaryViewType() {}

		static void Register(BinaryViewType* type);
		static Ref<BinaryViewType> GetByName(const std::string& name);
		static std::vector<Ref<BinaryViewType>> GetViewTypes();
		static std::vector<Ref<BinaryViewType>> GetViewTypesForData(BinaryView* data);

		static void RegisterArchitecture(const std::string& name, uint32_t id, BNEndianness endian, Architecture* arch);
		void RegisterArchitecture(uint32_t id, BNEndianness endian, Architecture* arch);
		Ref<Architecture> GetArchitecture(uint32_t id, BNEndianness endian);

		static void RegisterPlatform(const std::string& name, uint32_t id, Architecture* arch, Platform* platform);
		static void RegisterDefaultPlatform(const std::string& name, Architecture* arch, Platform* platform);
		void RegisterPlatform(uint32_t id, Architecture* arch, Platform* platform);
		void RegisterDefaultPlatform(Architecture* arch, Platform* platform);
		Ref<Platform> GetPlatform(uint32_t id, Architecture* arch);

		void RegisterPlatformRecognizer(uint64_t id, BNEndianness endian,
			const std::function<Ref<Platform>(BinaryView* view, Metadata*)>& callback);
		Ref<Platform> RecognizePlatform(uint64_t id, BNEndianness endian, BinaryView* view, Metadata* metadata);

		std::string GetName();
		std::string GetLongName();

		virtual bool IsDeprecated();

		virtual BinaryView* Create(BinaryView* data) = 0;
		virtual BinaryView* Parse(BinaryView* data) = 0;
		virtual bool IsTypeValidForData(BinaryView* data) = 0;
		virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) = 0;

		static void RegisterBinaryViewFinalizationEvent(const std::function<void(BinaryView* view)>& callback);
		static void RegisterBinaryViewInitialAnalysisCompletionEvent(
			const std::function<void(BinaryView* view)>& callback);

		static void BinaryViewEventCallback(void* ctxt, BNBinaryView* view);
		static BNPlatform* PlatformRecognizerCallback(void* ctxt, BNBinaryView* view, BNMetadata* metadata);
	};

	class CoreBinaryViewType : public BinaryViewType
	{
	  public:
		CoreBinaryViewType(BNBinaryViewType* type);
		virtual BinaryView* Create(BinaryView* data) override;
		virtual BinaryView* Parse(BinaryView* data) override;
		virtual bool IsTypeValidForData(BinaryView* data) override;
		virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override;
	};
}