#pragma once
#include "core/binaryninja_defs.h"
#include "core/qualifiedname.h"

extern "C" {

	struct BNArchitecture;
	struct BNCallingConvention;
	struct BNPlatform;
	struct BNQualifiedName;
	struct BNQualifiedNameAndType;
	struct BNSystemCallInfo;
	struct BNType;
	struct BNTypeLibrary;

	struct BNSystemCallInfo
	{
		uint32_t number;
		BNQualifiedName name;
		BNType* type;
	};

	// Platforms
	BINARYNINJACOREAPI BNPlatform* BNCreatePlatform(BNArchitecture* arch, const char* name);
	BINARYNINJACOREAPI BNPlatform* BNCreatePlatformWithTypes(
		BNArchitecture* arch, const char* name, const char* typeFile, const char** includeDirs, size_t includeDirCount);
	BINARYNINJACOREAPI void BNRegisterPlatform(const char* os, BNPlatform* platform);
	BINARYNINJACOREAPI BNPlatform* BNNewPlatformReference(BNPlatform* platform);
	BINARYNINJACOREAPI void BNFreePlatform(BNPlatform* platform);

	BINARYNINJACOREAPI char* BNGetPlatformName(BNPlatform* platform);
	BINARYNINJACOREAPI BNArchitecture* BNGetPlatformArchitecture(BNPlatform* platform);

	BINARYNINJACOREAPI BNPlatform* BNGetPlatformByName(const char* name);
	BINARYNINJACOREAPI BNPlatform** BNGetPlatformList(size_t* count);
	BINARYNINJACOREAPI BNPlatform** BNGetPlatformListByArchitecture(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI BNPlatform** BNGetPlatformListByOS(const char* os, size_t* count);
	BINARYNINJACOREAPI BNPlatform** BNGetPlatformListByOSAndArchitecture(
		const char* os, BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI void BNFreePlatformList(BNPlatform** platform, size_t count);
	BINARYNINJACOREAPI char** BNGetPlatformOSList(size_t* count);
	BINARYNINJACOREAPI void BNFreePlatformOSList(char** list, size_t count);

	BINARYNINJACOREAPI BNCallingConvention* BNGetPlatformDefaultCallingConvention(BNPlatform* platform);
	BINARYNINJACOREAPI BNCallingConvention* BNGetPlatformCdeclCallingConvention(BNPlatform* platform);
	BINARYNINJACOREAPI BNCallingConvention* BNGetPlatformStdcallCallingConvention(BNPlatform* platform);
	BINARYNINJACOREAPI BNCallingConvention* BNGetPlatformFastcallCallingConvention(BNPlatform* platform);
	BINARYNINJACOREAPI BNCallingConvention** BNGetPlatformCallingConventions(BNPlatform* platform, size_t* count);
	BINARYNINJACOREAPI BNCallingConvention* BNGetPlatformSystemCallConvention(BNPlatform* platform);

	BINARYNINJACOREAPI void BNRegisterPlatformCallingConvention(BNPlatform* platform, BNCallingConvention* cc);
	BINARYNINJACOREAPI void BNRegisterPlatformDefaultCallingConvention(BNPlatform* platform, BNCallingConvention* cc);
	BINARYNINJACOREAPI void BNRegisterPlatformCdeclCallingConvention(BNPlatform* platform, BNCallingConvention* cc);
	BINARYNINJACOREAPI void BNRegisterPlatformStdcallCallingConvention(BNPlatform* platform, BNCallingConvention* cc);
	BINARYNINJACOREAPI void BNRegisterPlatformFastcallCallingConvention(BNPlatform* platform, BNCallingConvention* cc);
	BINARYNINJACOREAPI void BNSetPlatformSystemCallConvention(BNPlatform* platform, BNCallingConvention* cc);

	BINARYNINJACOREAPI BNPlatform* BNGetArchitectureStandalonePlatform(BNArchitecture* arch);

	BINARYNINJACOREAPI BNPlatform* BNGetRelatedPlatform(BNPlatform* platform, BNArchitecture* arch);
	BINARYNINJACOREAPI void BNAddRelatedPlatform(BNPlatform* platform, BNArchitecture* arch, BNPlatform* related);
	BINARYNINJACOREAPI BNPlatform* BNGetAssociatedPlatformByAddress(BNPlatform* platform, uint64_t* addr);

	BINARYNINJACOREAPI BNQualifiedNameAndType* BNGetPlatformTypes(BNPlatform* platform, size_t* count);
	BINARYNINJACOREAPI BNQualifiedNameAndType* BNGetPlatformVariables(BNPlatform* platform, size_t* count);
	BINARYNINJACOREAPI BNQualifiedNameAndType* BNGetPlatformFunctions(BNPlatform* platform, size_t* count);
	BINARYNINJACOREAPI BNSystemCallInfo* BNGetPlatformSystemCalls(BNPlatform* platform, size_t* count);
	BINARYNINJACOREAPI void BNFreeSystemCallList(BNSystemCallInfo* syscalls, size_t count);
	BINARYNINJACOREAPI BNType* BNGetPlatformTypeByName(BNPlatform* platform, BNQualifiedName* name);
	BINARYNINJACOREAPI BNType* BNGetPlatformVariableByName(BNPlatform* platform, BNQualifiedName* name);
	BINARYNINJACOREAPI BNType* BNGetPlatformFunctionByName(
		BNPlatform* platform, BNQualifiedName* name, bool exactMatch);
	BINARYNINJACOREAPI char* BNGetPlatformSystemCallName(BNPlatform* platform, uint32_t number);
	BINARYNINJACOREAPI BNType* BNGetPlatformSystemCallType(BNPlatform* platform, uint32_t number);

	BINARYNINJACOREAPI BNTypeLibrary** BNGetPlatformTypeLibraries(BNPlatform* platform, size_t* count);
	BINARYNINJACOREAPI BNTypeLibrary** BNGetPlatformTypeLibrariesByName(
		BNPlatform* platform, char* depName, size_t* count);
}