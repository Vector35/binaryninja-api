#pragma once

#include "binaryninjacore.h"
#include "refcount.h"
#include <string>
#include <vector>

namespace BinaryNinja
{
	class BinaryView;

	/*! \c Settings provides a way to define and access settings in a hierarchical fashion. The value of a setting can
		be defined for each hierarchical level, where each level overrides the preceding level. The backing-store for setting
		values at each level is also configurable. This allows for ephemeral or platform-independent persistent settings storage
		for components within Binary Ninja or consumers of the Binary Ninja API.

		Each \c Settings instance has an \c instanceId which identifies a schema. The schema defines the settings contents
		and the way in which settings are retrieved and manipulated. A new \c Settings instance defaults to using a value of <em><tt>default</tt></em>
		for the \c instanceId . The <em><tt>default</tt></em> settings schema defines all of the settings available for the active Binary Ninja components
		which include at a minimum, the settings defined by the Binary Ninja core. The <em><tt>default</tt></em> schema may additionally define settings
		for the UI and/or installed plugins. Extending existing schemas, or defining new ones is accomplished by calling \c RegisterGroup()
		and \c RegisterSetting() methods, or by deserializing an existing schema with \c DeserializeSchema() .

		\note All settings in the <em><tt>default</tt></em> settings schema are rendered with UI elements in the Settings View of Binary Ninja UI.

		Allowing setting overrides is an important feature and Binary Ninja accomplishes this by allowing one to override a setting at various
		levels. The levels and their associated storage are shown in the following table. Default setting values are optional, and if specified,
		saved in the schema itself.

			================= ========================== ============== ==============================================
			Setting Level     Settings Scope             Preference     Storage
			================= ========================== ============== ==============================================
			Default           SettingsDefaultScope       Lowest         Settings Schema
			User              SettingsUserScope          -              <User Directory>/settings.json
			Project           SettingsProjectScope       -              <Project Directory>/settings.json
			Resource          SettingsResourceScope      Highest        Raw BinaryView (Storage in BNDB)
			================= ========================== ============== ==============================================

		Settings are identified by a key, which is a string in the form of <b><tt><group>.<name></tt></b> or <b><tt><group>.<subGroup>.<name></tt></b> . Groups provide
		a simple way to categorize settings. Sub-groups are optional and multiple sub-groups are allowed. When defining a settings group, the
		\c RegisterGroup method allows for specifying a UI friendly title for use in the Binary Ninja UI. Defining a new setting requires a
		unique setting key and a JSON string of property, value pairs. The following table describes the available properties and values.

			==================   ======================================   ==================   ========   =======================================================================
			Property             JSON Data Type                           Prerequisite         Optional   {Allowed Values} and Notes
			==================   ======================================   ==================   ========   =======================================================================
			"title"              string                                   None                 No         Concise Setting Title
			"type"               string                                   None                 No         {"array", "boolean", "number", "string"}
			"elementType"        string                                   "type" is "array"    No         {"string"}
			"enum"               array : {string}                         "type" is "array"    Yes        Enumeration definitions
			"enumDescriptions"   array : {string}                         "type" is "array"    Yes        Enumeration descriptions that match "enum" array
			"minValue"           number                                   "type" is "number"   Yes        Specify 0 to infer unsigned (default is signed)
			"maxValue"           number                                   "type" is "number"   Yes        Values less than or equal to INT_MAX result in a QSpinBox UI element
			"precision"          number                                   "type" is "number"   Yes        Specify precision for a QDoubleSpinBox
			"default"            {array, boolean, number, string, null}   None                 Yes        Specify optimal default value
			"aliases"            array : {string}                         None                 Yes        Array of deprecated setting key(s)
			"description"        string                                   None                 No         Detailed setting description
			"ignore"             array : {string}                         None                 Yes        {"SettingsUserScope", "SettingsProjectScope", "SettingsResourceScope"}
			"message"            string                                   None                 Yes        An optional message with additional emphasis
			"readOnly"           bool                                     None                 Yes        Only enforced by UI elements
			"optional"           bool                                     None                 Yes        Indicates setting can be null
			"hidden"             bool                                     "type" is "string"   Yes        Indicates the UI should conceal the content. The "ignore" property is required to specify the applicable storage scopes
			"requiresRestart     bool                                     None                 Yes        Enable restart notification in the UI upon change
			"uiSelectionAction"  string                                   "type" is "string"   Yes        {"file", "directory", <Registered UIAction Name>} Informs the UI to add a button to open a selection dialog or run a registered UIAction
			==================   ======================================   ==================   ========   =======================================================================

		\note In order to facilitate deterministic analysis results, settings from the <em><tt>default</tt></em> schema that impact analysis are serialized
		from Default, User, and Project scope into Resource scope during initial BinaryView analysis. This allows an analysis database to be opened
		at a later time with the same settings, regardless if Default, User, or Project settings have been modified.

		\note Settings that do not impact analysis (e.g. many UI settings) should use the \e "ignore" property to exclude
			\e "SettingsProjectScope" and \e "SettingsResourceScope" from the applicable scopes for the setting.

		<b>Example analysis plugin setting:</b>
	 	\code{.cpp}
		auto settings = Settings::Instance()

	 	settings->RegisterGroup("myPlugin", "My Plugin")

		settings->RegisterSetting("myPlugin.enablePreAnalysis",
			R"~({
			"title": "My Pre-Analysis Plugin",
			"type": "boolean",
			"default": false,
			"description": "Enable extra analysis before core analysis.",
			"ignore": ["SettingsProjectScope", "SettingsResourceScope"]
			})~");

		Metadata options = {{"myPlugin.enablePreAnalysis", Metadata(true)}};
		Ref<BinaryView> bv = Load("/bin/ls", true, {}, options);

		Settings::Instance()->Get<bool>("myPlugin.enablePreAnalysis"); // false
	    Settings::Instance()->Get<bool>("myPlugin.enablePreAnalysis", bv); // true
		\endcode

	 	<b>Getting a settings value:</b>
	 	\code{.cpp}
	    bool excludeUnreferencedStrings = Settings::Instance()->Get<bool>("ui.stringView.excludeUnreferencedStrings", bv);
	    \endcode

	    \ingroup settings
	*/
	class Settings : public CoreRefCountObject<BNSettings, BNNewSettingsReference, BNFreeSettings>
	{
		std::string m_instanceId;

		Settings() = delete;
		Settings(const std::string& m_instanceId);

	  public:
		Settings(BNSettings* settings);
		static Ref<Settings> Instance(const std::string& schemaId = "");
		virtual ~Settings() {}

		/*! Sets the file that this \c Settings instance uses when initially loading, and modifying \
			settings for the specified scope.

			\note At times it may be useful to make ephemeral changes to settings that are not saved to file. This can be accomplished \
			by calling \c LoadSettingsFile without specifying a filename. This action also resets settings to their default value.

			\param fileName the settings filename
			\param scope the BNSettingsScope
			\param view a BinaryView object
			\return True if the load is successful, False otherwise
		*/
		bool LoadSettingsFile(const std::string& fileName, BNSettingsScope scope = SettingsAutoScope, Ref<BinaryView> view = nullptr);

		/*! Sets the resource identifier for this \c Settings instance. When accessing setting values at the
			\c SettingsResourceScope level, the resource identifier is passed along through the backing store interface.

			\note Currently the only available backing store for \c SettingsResourceScope is a \c BinaryView object. In the context
			of a \c BinaryView the resource identifier is the \c BinaryViewType name. All settings for this type of backing store
			are saved in the \e 'Raw' \c BinaryViewType . This enables the configuration of setting values such that they are available
			during \c BinaryView creation and initialization.

			\param resourceId a unique identifier
		*/
		void SetResourceId(const std::string& resourceId = "");

		/*! Registers a group in the schema for this \c Settings instance

			\param group a unique identifier
			\param title a user friendly name appropriate for UI presentation
			\return True on success, False on failure
		*/
		bool RegisterGroup(const std::string& group, const std::string& title);

		/*! Registers a new setting with this \c Settings instance

			\param key a unique setting identifier in the form <b>'<group>.<name>'</b>
			\param properties a JSON string describes the setting schema
			\return True on success, False on failure.
		*/
		bool RegisterSetting(const std::string& key, const std::string& properties);

		/*! Determine if a setting identifier exists in the active settings schema

			\param key the setting identifier
			\return True if the identifier exists in this active settings schema, False otherwise
		*/
		bool Contains(const std::string& key);

		/*! Determine if the active settings schema is empty

			\return True if the active settings schema is empty, False otherwise
		*/
		bool IsEmpty();

		/*! Retrieve the list of setting identifiers in the active settings schema

			\return List of setting identifiers
		*/
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

		/*! Get the current setting value for a particular key

			\code{.cpp}
		 	bool excludeUnreferencedStrings = Settings::Instance()->Get<bool>("ui.stringView.excludeUnreferencedStrings", data);
			\endcode

			\tparam T type for the value you are retrieving
			\param key Key for the setting
			\param view BinaryView, for factoring in resource-scoped settings
			\param scope Scope for the settings
			\return Value for the setting, with type T
		*/
		template <typename T>
		T Get(const std::string& key, Ref<BinaryView> view = nullptr, BNSettingsScope* scope = nullptr);

		/*! Get the current settings value for a particular key, as a JSON representation of its value.

			\code{.cpp}
		    string value = Settings::Instance()->GetJson("analysis.mode");
			// '"full"'
		 	\endcode

			\param key Key for the setting
			\param view BinaryView, for factoring in resource-scoped settings
			\param scope Scope for the settings
			\return JSON value for the setting, as a string
		*/
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
	/*! \cond DOXYGEN_HIDE
		Prevent these from having docs autogenerated twice, due to an odd quirk with doxygen
	*/
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
	/*! \endcond*/


}
