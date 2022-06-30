#pragma once
#include "binaryninja_defs.h"

extern "C" {
	struct BNMetadata;

	enum BNMetadataType
	{
		InvalidDataType,
		BooleanDataType,
		StringDataType,
		UnsignedIntegerDataType,
		SignedIntegerDataType,
		DoubleDataType,
		RawDataType,
		KeyValueDataType,
		ArrayDataType
	};

	struct BNMetadataValueStore
	{
		size_t size;
		char** keys;
		BNMetadata** values;
	};

	// Create Metadata of various types
	BINARYNINJACOREAPI BNMetadata* BNNewMetadataReference(BNMetadata* data);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataBooleanData(bool data);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataStringData(const char* data);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataUnsignedIntegerData(uint64_t data);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataSignedIntegerData(int64_t data);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataDoubleData(double data);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataOfType(BNMetadataType type);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataRawData(const uint8_t* data, size_t size);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataArray(BNMetadata** data, size_t size);
	BINARYNINJACOREAPI BNMetadata* BNCreateMetadataValueStore(const char** keys, BNMetadata** values, size_t size);

	BINARYNINJACOREAPI bool BNMetadataIsEqual(BNMetadata* lhs, BNMetadata* rhs);

	BINARYNINJACOREAPI bool BNMetadataSetValueForKey(BNMetadata* data, const char* key, BNMetadata* md);
	BINARYNINJACOREAPI BNMetadata* BNMetadataGetForKey(BNMetadata* data, const char* key);
	BINARYNINJACOREAPI bool BNMetadataArrayAppend(BNMetadata* data, BNMetadata* md);
	BINARYNINJACOREAPI void BNMetadataRemoveKey(BNMetadata* data, const char* key);
	BINARYNINJACOREAPI size_t BNMetadataSize(BNMetadata* data);
	BINARYNINJACOREAPI BNMetadata* BNMetadataGetForIndex(BNMetadata* data, size_t index);
	BINARYNINJACOREAPI void BNMetadataRemoveIndex(BNMetadata* data, size_t index);

	BINARYNINJACOREAPI void BNFreeMetadataArray(BNMetadata** data);
	BINARYNINJACOREAPI void BNFreeMetadataValueStore(BNMetadataValueStore* data);
	BINARYNINJACOREAPI void BNFreeMetadata(BNMetadata* data);
	BINARYNINJACOREAPI void BNFreeMetadataRaw(uint8_t* data);
	// Retrieve Structured Data
	BINARYNINJACOREAPI bool BNMetadataGetBoolean(BNMetadata* data);
	BINARYNINJACOREAPI char* BNMetadataGetString(BNMetadata* data);
	BINARYNINJACOREAPI uint64_t BNMetadataGetUnsignedInteger(BNMetadata* data);
	BINARYNINJACOREAPI int64_t BNMetadataGetSignedInteger(BNMetadata* data);
	BINARYNINJACOREAPI double BNMetadataGetDouble(BNMetadata* data);
	BINARYNINJACOREAPI uint8_t* BNMetadataGetRaw(BNMetadata* data, size_t* size);
	BINARYNINJACOREAPI BNMetadata** BNMetadataGetArray(BNMetadata* data, size_t* size);
	BINARYNINJACOREAPI BNMetadataValueStore* BNMetadataGetValueStore(BNMetadata* data);

	// Query type of Metadata
	BINARYNINJACOREAPI BNMetadataType BNMetadataGetType(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsBoolean(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsString(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsUnsignedInteger(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsSignedInteger(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsDouble(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsRaw(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsArray(BNMetadata* data);
	BINARYNINJACOREAPI bool BNMetadataIsKeyValueStore(BNMetadata* data);
}