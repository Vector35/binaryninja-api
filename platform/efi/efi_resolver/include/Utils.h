#pragma once

#include "binaryninjaapi.h"

using namespace BinaryNinja;

static inline std::string GetOriginalTypeName(Ref<Type> type)
{
    std::string result;
    if (type->IsPointer()) {
        if (type->GetChildType().GetValue()->IsNamedTypeRefer()) {
            return type->GetChildType().GetValue()->GetNamedTypeReference()->GetName().GetString();
        }
        return type->GetTypeName().GetString();
    }
    if (type->IsNamedTypeRefer())
        return type->GetNamedTypeReference()->GetName().GetString();

    return type->GetTypeName().GetString();
}

static inline std::string GetVarNameForTypeStr(const std::string typeStr)
{
    std::istringstream iss(typeStr);
    std::string word;
    std::string result;

    while (std::getline(iss, word, '_')) {
        if (!word.empty()) {
            word[0] = std::toupper(word[0]);
            std::transform(word.begin() + 1, word.end(), word.begin() + 1, ::tolower);
            result += word;
        }
    }
    return result;
}
