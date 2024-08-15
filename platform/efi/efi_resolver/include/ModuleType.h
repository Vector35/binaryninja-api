#pragma once

#include "binaryninjaapi.h"

using namespace BinaryNinja;

enum EFIModuleType {
    UNKNOWN,
    PEI,
    DXE,
};

static inline EFIModuleType identifyModuleType(BinaryView* bv)
{
    std::string viewType = bv->GetCurrentView();
    if (viewType == "Linear:PE")
        return DXE;
    else if (viewType == "Linear:TE")
        return PEI;
    else
        return UNKNOWN;
}