#pragma once
#include "binaryninjaapi.h"

class ObjCActivity
{
    static void AdjustCallType(BinaryNinja::Ref<BinaryNinja::AnalysisContext> ctx);
public:
    static void Register(BinaryNinja::Workflow& workflow);
};