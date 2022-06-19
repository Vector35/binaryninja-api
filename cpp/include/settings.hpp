#pragma once
#include <vector>
#include <string>
#include "refcount.hpp"
#include "core/binaryninja_defs.h"
#include "core/settings.h"

namespace BinaryNinja {
	class BinaryView;
	class Settings : public CoreRefCountObject<BNSettings, BNNewSettingsReference, BNFreeSettings>
	{
		std::string m_instanceId;

		Settings() = delete;
		Settings(const std::string& m_instanceId);

	  public:
		Settings(BNSettings* settings);
		static Ref<Settings> Instance(const std::string& schemaId = "");
		virtual ~Settings() {}

		void SetResourceId(const std::string& resourceId = "");

		bool RegisterGroup(const std::string& group, const std::string& title);
		bool RegisterSetting(const std::string& key, const std::string& properties);
		bool Contains(const std::string& key);
		bool IsEmpty();
		std::vector<std::string> Keys();

		template <typename T>
		T QueryProperty(const std::string& key, const std::string& property);

		bool UpdateProperty(const std::string& key, const std::string& property);
		bool UpdateProperty(const std::string& key, const std::string& property, bool value);
		bool UpdateProperty(const std::string& key, const std::string& property, double value);
		bool UpdateProperty(const std::string& key, const std::string& property, int value);
		bool UpdateProperty(const std::string& key, const std::string& property, int64_t value);
		bool UpdateProperty(const std::string& key, const std::string& property, uint64_t value);
		bool UpdateProperty(const std::string& key, const std::string& property, const char* value);
		bool UpdateProperty(const std::string& key, const std::string& property, const std::string& value);
		bool UpdateProperty(const std::string& key, const std::string& property, const std::vector<std::string>& value);

		bool DeserializeSchema(const std::string& schema, BNSettingsScope scope = SettingsAutoScope, bool merge = true);
		std::string SerializeSchema();
		bool DeserializeSettings(
			const std::string& contents, Ref<BinaryView> view = nullptr, BNSettingsScope scope = SettingsAutoScope);
		std::string SerializeSettings(Ref<BinaryView> view = nullptr, BNSettingsScope scope = SettingsAutoScope);

		bool Reset(const std::string& key, Ref<BinaryView> view = nullptr, BNSettingsScope scope = SettingsAutoScope);
		bool ResetAll(
			Ref<BinaryView> view = nullptr, BNSettingsScope scope = SettingsAutoScope, bool schemaOnly = true);

		template <typename T>
		T Get(const std::string& key, Ref<BinaryView> view = nullptr, BNSettingsScope* scope = nullptr);
		std::string GetJson(const std::string& key, Ref<BinaryView> view = nullptr, BNSettingsScope* scope = nullptr);

		bool Set(const std::string& key, bool value, Ref<BinaryView> view = nullptr,
			BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, double value, Ref<BinaryView> view = nullptr,
			BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, int value, Ref<BinaryView> view = nullptr,
			BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, int64_t value, Ref<BinaryView> view = nullptr,
			BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, uint64_t value, Ref<BinaryView> view = nullptr,
			BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, const char* value, Ref<BinaryView> view = nullptr,
			BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, const std::string& value, Ref<BinaryView> view = nullptr,
			BNSettingsScope scope = SettingsAutoScope);
		bool Set(const std::string& key, const std::vector<std::string>& value, Ref<BinaryView> view = nullptr,
			BNSettingsScope scope = SettingsAutoScope);
		bool SetJson(const std::string& key, const std::string& value, Ref<BinaryView> view = nullptr,
			BNSettingsScope scope = SettingsAutoScope);
	};

	// explicit specializations
	template <>
	std::vector<std::string> Settings::QueryProperty<std::vector<std::string>>(
	    const std::string& key, const std::string& property);
	template <>
	bool Settings::Get<bool>(const std::string& key, Ref<BinaryView> view, BNSettingsScope* scope);
	template <>
	double Settings::Get<double>(const std::string& key, Ref<BinaryView> view, BNSettingsScope* scope);
	template <>
	int64_t Settings::Get<int64_t>(const std::string& key, Ref<BinaryView> view, BNSettingsScope* scope);
	template <>
	uint64_t Settings::Get<uint64_t>(const std::string& key, Ref<BinaryView> view, BNSettingsScope* scope);
	template <>
	std::string Settings::Get<std::string>(const std::string& key, Ref<BinaryView> view, BNSettingsScope* scope);
	template <>
	std::vector<std::string> Settings::Get<std::vector<std::string>>(
	    const std::string& key, Ref<BinaryView> view, BNSettingsScope* scope);

}