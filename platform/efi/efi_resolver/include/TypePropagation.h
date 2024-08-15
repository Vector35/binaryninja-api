#pragma once

#include "Utils.h"
#include "binaryninjaapi.h"

using namespace BinaryNinja;

class TypePropagation {
    Ref<BinaryView> m_view;
    std::deque<uint64_t> m_queue;
    Ref<Platform> m_platform;

public:
    TypePropagation(BinaryView* view);
    bool propagateFuncParamTypes(Function* func);
    bool propagateFuncParamTypes(Function* func, SSAVariable ssa_var);
};