#pragma once

#include "core/binaryninja_defs.h"

extern "C" {
    struct BNSettings;
    struct BNBinaryView;

	enum BNSettingsScope
	{
		SettingsInvalidScope = 0,
		SettingsAutoScope = 1,
		SettingsDefaultScope = 2,
		SettingsUserScope = 4,
		SettingsProjectScope = 8,
		SettingsResourceScope = 0x10
	};

    // Settings APIs
	BINARYNINJACOREAPI BNSettings* BNCreateSettings(const char* schemaId);
	BINARYNINJACOREAPI BNSettings* BNNewSettingsReference(BNSettings* settings);
	BINARYNINJACOREAPI void BNFreeSettings(BNSettings* settings);
	BINARYNINJACOREAPI void BNSettingsSetResourceId(BNSettings* settings, const char* resourceId);
	BINARYNINJACOREAPI bool BNSettingsRegisterGroup(BNSettings* settings, const char* group, const char* title);
	BINARYNINJACOREAPI bool BNSettingsRegisterSetting(BNSettings* settings, const char* key, const char* properties);
	BINARYNINJACOREAPI bool BNSettingsContains(BNSettings* settings, const char* key);
	BINARYNINJACOREAPI bool BNSettingsIsEmpty(BNSettings* settings);
	BINARYNINJACOREAPI const char** BNSettingsKeysList(BNSettings* settings, size_t* inoutSize);
	BINARYNINJACOREAPI const char** BNSettingsQueryPropertyStringList(
	    BNSettings* settings, const char* key, const char* property, size_t* inoutSize);
	BINARYNINJACOREAPI bool BNSettingsUpdateProperty(BNSettings* settings, const char* key, const char* property);
	BINARYNINJACOREAPI bool BNSettingsUpdateBoolProperty(
	    BNSettings* settings, const char* key, const char* property, bool value);
	BINARYNINJACOREAPI bool BNSettingsUpdateDoubleProperty(
	    BNSettings* settings, const char* key, const char* property, double value);
	BINARYNINJACOREAPI bool BNSettingsUpdateInt64Property(
	    BNSettings* settings, const char* key, const char* property, int64_t value);
	BINARYNINJACOREAPI bool BNSettingsUpdateUInt64Property(
	    BNSettings* settings, const char* key, const char* property, uint64_t value);
	BINARYNINJACOREAPI bool BNSettingsUpdateStringProperty(
	    BNSettings* settings, const char* key, const char* property, const char* value);
	BINARYNINJACOREAPI bool BNSettingsUpdateStringListProperty(
	    BNSettings* settings, const char* key, const char* property, const char** value, size_t size);

	BINARYNINJACOREAPI bool BNSettingsDeserializeSchema(
	    BNSettings* settings, const char* schema, BNSettingsScope scope, bool merge);
	BINARYNINJACOREAPI char* BNSettingsSerializeSchema(BNSettings* settings);
	BINARYNINJACOREAPI bool BNDeserializeSettings(
	    BNSettings* settings, const char* contents, BNBinaryView* view, BNSettingsScope scope);
	BINARYNINJACOREAPI char* BNSerializeSettings(BNSettings* settings, BNBinaryView* view, BNSettingsScope scope);

	BINARYNINJACOREAPI bool BNSettingsReset(
	    BNSettings* settings, const char* key, BNBinaryView* view, BNSettingsScope scope);
	BINARYNINJACOREAPI bool BNSettingsResetAll(
	    BNSettings* settings, BNBinaryView* view, BNSettingsScope scope, bool schemaOnly);

	BINARYNINJACOREAPI bool BNSettingsGetBool(
	    BNSettings* settings, const char* key, BNBinaryView* view, BNSettingsScope* scope);
	BINARYNINJACOREAPI double BNSettingsGetDouble(
	    BNSettings* settings, const char* key, BNBinaryView* view, BNSettingsScope* scope);
	BINARYNINJACOREAPI int64_t BNSettingsGetInt64(
	    BNSettings* settings, const char* key, BNBinaryView* view, BNSettingsScope* scope);
	BINARYNINJACOREAPI uint64_t BNSettingsGetUInt64(
	    BNSettings* settings, const char* key, BNBinaryView* view, BNSettingsScope* scope);
	BINARYNINJACOREAPI char* BNSettingsGetString(
	    BNSettings* settings, const char* key, BNBinaryView* view, BNSettingsScope* scope);
	BINARYNINJACOREAPI const char** BNSettingsGetStringList(
	    BNSettings* settings, const char* key, BNBinaryView* view, BNSettingsScope* scope, size_t* inoutSize);
	BINARYNINJACOREAPI char* BNSettingsGetJson(
	    BNSettings* settings, const char* key, BNBinaryView* view, BNSettingsScope* scope);

	BINARYNINJACOREAPI bool BNSettingsSetBool(
	    BNSettings* settings, BNBinaryView* view, BNSettingsScope scope, const char* key, bool value);
	BINARYNINJACOREAPI bool BNSettingsSetDouble(
	    BNSettings* settings, BNBinaryView* view, BNSettingsScope scope, const char* key, double value);
	BINARYNINJACOREAPI bool BNSettingsSetInt64(
	    BNSettings* settings, BNBinaryView* view, BNSettingsScope scope, const char* key, int64_t value);
	BINARYNINJACOREAPI bool BNSettingsSetUInt64(
	    BNSettings* settings, BNBinaryView* view, BNSettingsScope scope, const char* key, uint64_t value);
	BINARYNINJACOREAPI bool BNSettingsSetString(
	    BNSettings* settings, BNBinaryView* view, BNSettingsScope scope, const char* key, const char* value);
	BINARYNINJACOREAPI bool BNSettingsSetStringList(BNSettings* settings, BNBinaryView* view, BNSettingsScope scope,
	    const char* key, const char** value, size_t size);
	BINARYNINJACOREAPI bool BNSettingsSetJson(
	    BNSettings* settings, BNBinaryView* view, BNSettingsScope scope, const char* key, const char* value);

}