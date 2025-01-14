#pragma once

#include "binaryninjaapi.h"

using namespace BinaryNinja;

enum EFIModuleType
{
	UNKNOWN,
	PEI,
	DXE,
};

static inline EFIModuleType identifyModuleType(BinaryView* bv)
{
	FileMetadata* file = bv->GetFile();
	if (file->GetViewOfType("PE"))
		return DXE;
	else if (file->GetViewOfType("TE"))
		return PEI;
	else
		return UNKNOWN;
}