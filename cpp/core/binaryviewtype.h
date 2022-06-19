#pragma once

#include "core/binaryninja_defs.h"

extern "C" {
	struct BNArchitecture;
	struct BNBinaryView;
	struct BNBinaryViewType;
	struct BNCustomBinaryViewType;
	struct BNDataBuffer;
	struct BNFileAccessor;
	struct BNFileMetadata;
	struct BNMetadata;
	struct BNPlatform;
	struct BNSettings;

	struct BNCustomBinaryViewType
	{
		void* context;
		BNBinaryView* (*create)(void* ctxt, BNBinaryView* data);
		BNBinaryView* (*parse)(void* ctxt, BNBinaryView* data);
		bool (*isValidForData)(void* ctxt, BNBinaryView* data);
		bool (*isDeprecated)(void* ctxt);
		BNSettings* (*getLoadSettingsForData)(void* ctxt, BNBinaryView* data);
	};

	enum BNBinaryViewEventType
	{
		BinaryViewFinalizationEvent,
		BinaryViewInitialAnalysisCompletionEvent
	};

	struct BNBinaryViewEvent
	{
		BNBinaryViewEventType type;
		void (*callback)(void* ctx, BNBinaryView* view);
		void* ctx;
	};

	BINARYNINJACOREAPI BNBinaryViewType* BNGetBinaryViewTypeByName(const char* name);
	BINARYNINJACOREAPI BNBinaryViewType** BNGetBinaryViewTypes(size_t* count);
	BINARYNINJACOREAPI BNBinaryViewType** BNGetBinaryViewTypesForData(BNBinaryView* data, size_t* count);
	BINARYNINJACOREAPI void BNFreeBinaryViewTypeList(BNBinaryViewType** types);
	BINARYNINJACOREAPI char* BNGetBinaryViewTypeName(BNBinaryViewType* type);
	BINARYNINJACOREAPI char* BNGetBinaryViewTypeLongName(BNBinaryViewType* type);
	BINARYNINJACOREAPI bool BNIsBinaryViewTypeDeprecated(BNBinaryViewType* type);
	BINARYNINJACOREAPI BNBinaryView* BNCreateBinaryViewOfType(BNBinaryViewType* type, BNBinaryView* data);
	BINARYNINJACOREAPI BNBinaryView* BNParseBinaryViewOfType(BNBinaryViewType* type, BNBinaryView* data);
	BINARYNINJACOREAPI bool BNIsBinaryViewTypeValidForData(BNBinaryViewType* type, BNBinaryView* data);
	BINARYNINJACOREAPI BNSettings* BNGetBinaryViewDefaultLoadSettingsForData(
		BNBinaryViewType* type, BNBinaryView* data);
	BINARYNINJACOREAPI BNSettings* BNGetBinaryViewLoadSettingsForData(BNBinaryViewType* type, BNBinaryView* data);

	BINARYNINJACOREAPI BNBinaryViewType* BNRegisterBinaryViewType(
		const char* name, const char* longName, BNCustomBinaryViewType* type);

	BINARYNINJACOREAPI void BNRegisterArchitectureForViewType(BNBinaryViewType* type, uint32_t id, BNEndianness endian,
		BNArchitecture* arch);  // Deprecated, use BNRegisterPlatformRecognizerForViewType
	BINARYNINJACOREAPI BNArchitecture* BNGetArchitectureForViewType(BNBinaryViewType* type, uint32_t id,
		BNEndianness endian);  // Deprecated, use BNRecognizePlatformForViewType

	BINARYNINJACOREAPI void BNRegisterPlatformForViewType(BNBinaryViewType* type, uint32_t id, BNArchitecture* arch,
		BNPlatform* platform);  // Deprecated, use BNRegisterPlatformRecognizerForViewType
	BINARYNINJACOREAPI BNPlatform* BNGetPlatformForViewType(
		BNBinaryViewType* type, uint32_t id, BNArchitecture* arch);  // Deprecated, use BNRecognizePlatformForViewType

	BINARYNINJACOREAPI void BNRegisterDefaultPlatformForViewType(
		BNBinaryViewType* type, BNArchitecture* arch, BNPlatform* platform);

	// Raw binary data view
	BINARYNINJACOREAPI BNBinaryView* BNCreateBinaryDataView(BNFileMetadata* file);
	BINARYNINJACOREAPI BNBinaryView* BNCreateBinaryDataViewFromBuffer(BNFileMetadata* file, BNDataBuffer* buf);
	BINARYNINJACOREAPI BNBinaryView* BNCreateBinaryDataViewFromData(BNFileMetadata* file, const void* data, size_t len);
	BINARYNINJACOREAPI BNBinaryView* BNCreateBinaryDataViewFromFilename(BNFileMetadata* file, const char* filename);
	BINARYNINJACOREAPI BNBinaryView* BNCreateBinaryDataViewFromFile(BNFileMetadata* file, BNFileAccessor* accessor);

	// Expanded identification of Platform for BinaryViewTypes. Supersedes BNRegisterArchitectureForViewType
	// and BNRegisterPlatformForViewType, as these have certain edge cases (overloaded elf families, for example)
	// that can't be represented.
	//
	// The callback returns a Platform object or null (failure), and most recently added callbacks are called first
	// to allow plugins to override any default behaviors. When a callback returns a platform, architecture will be
	// derived from the identified platform.
	//
	// The BinaryView pointer is the *parent* view (usually 'Raw') that the BinaryView is being created for. This
	// means that generally speaking the callbacks need to be aware of the underlying file format, however the
	// BinaryView implementation may have created datavars in the 'Raw' view by the time the callback is invoked.
	// Behavior regarding when this callback is invoked and what has been made available in the BinaryView passed as an
	// argument to the callback is up to the discretion of the BinaryView implementation.
	//
	// The 'id' ind 'endian' arguments are used as a filter to determine which registered Platform recognizer callbacks
	// are invoked.
	//
	// Support for this API tentatively requires explicit support in the BinaryView implementation.
	BINARYNINJACOREAPI void BNRegisterPlatformRecognizerForViewType(BNBinaryViewType* type, uint64_t id,
	    BNEndianness endian, BNPlatform* (*callback)(void* ctx, BNBinaryView* view, BNMetadata* metadata), void* ctx);

	// BinaryView* passed in here should be the parent view (not the partially constructed object!), and this function
	// should be called from the BNCustomBinaryView::init implementation.
	//
	// 'id' and 'endianness' are used to determine which registered callbacks are actually invoked to eliminate some
	// common sources of boilerplate that all callbacks would have to implement otherwise. If these aren't applicable to
	// your binaryviewtype just use constants here and document them so that people registering Platform recognizers for
	// your view type know what to use.
	BINARYNINJACOREAPI BNPlatform* BNRecognizePlatformForViewType(
	    BNBinaryViewType* type, uint64_t id, BNEndianness endian, BNBinaryView* view, BNMetadata* metadata);


	BINARYNINJACOREAPI void BNRegisterBinaryViewEvent(
	    BNBinaryViewEventType type, void (*callback)(void* ctx, BNBinaryView* view), void* ctx);
}