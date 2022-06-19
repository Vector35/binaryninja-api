#pragma once
#include "core/databuffer.h"
#include "core/databuffer.h"

extern "C" {
    struct BNDataBuffer;
    struct BNTransform;

	enum BNTransformType
	{
		BinaryCodecTransform = 0,   // Two-way transform of data, binary input/output
		TextCodecTransform = 1,     // Two-way transform of data, encoder output is text
		UnicodeCodecTransform = 2,  // Two-way transform of data, encoder output is Unicode string (as UTF8)
		DecodeTransform = 3,        // One-way decode only
		BinaryEncodeTransform = 4,  // One-way encode only, output is binary
		TextEncodeTransform = 5,    // One-way encode only, output is text
		EncryptTransform = 6,       // Two-way encryption
		InvertingTransform = 7,     // Transform that can be undone by performing twice
		HashTransform = 8           // Hash function
	};

	struct BNTransformParameterInfo
	{
		char* name;
		char* longName;
		size_t fixedLength;  // Variable length if zero
	};

	struct BNTransformParameter
	{
		const char* name;
		BNDataBuffer* value;
	};

	struct BNCustomTransform
	{
		void* context;
		BNTransformParameterInfo* (*getParameters)(void* ctxt, size_t* count);
		void (*freeParameters)(BNTransformParameterInfo* params, size_t count);
		bool (*decode)(
		    void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);
		bool (*encode)(
		    void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);
	};

	// Transforms
	BINARYNINJACOREAPI BNTransform* BNGetTransformByName(const char* name);
	BINARYNINJACOREAPI BNTransform** BNGetTransformTypeList(size_t* count);
	BINARYNINJACOREAPI void BNFreeTransformTypeList(BNTransform** xforms);
	BINARYNINJACOREAPI BNTransform* BNRegisterTransformType(
	    BNTransformType type, const char* name, const char* longName, const char* group, BNCustomTransform* xform);

	BINARYNINJACOREAPI BNTransformType BNGetTransformType(BNTransform* xform);
	BINARYNINJACOREAPI char* BNGetTransformName(BNTransform* xform);
	BINARYNINJACOREAPI char* BNGetTransformLongName(BNTransform* xform);
	BINARYNINJACOREAPI char* BNGetTransformGroup(BNTransform* xform);
	BINARYNINJACOREAPI BNTransformParameterInfo* BNGetTransformParameterList(BNTransform* xform, size_t* count);
	BINARYNINJACOREAPI void BNFreeTransformParameterList(BNTransformParameterInfo* params, size_t count);
	BINARYNINJACOREAPI bool BNDecode(
	    BNTransform* xform, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);
	BINARYNINJACOREAPI bool BNEncode(
	    BNTransform* xform, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);

}