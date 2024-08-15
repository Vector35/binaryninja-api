#pragma once

#include "binaryninjaapi.h"
#include <iomanip>

using namespace BinaryNinja;
using namespace std;

class EfiGuidRenderer : public BinaryNinja::DataRenderer {
    EfiGuidRenderer() = default;

public:
    bool IsValidForData(BinaryView*, uint64_t address, Type*,
        vector<pair<Type*, size_t>>&) override;

    vector<DisassemblyTextLine> GetLinesForData(
        BinaryView*, uint64_t address, Type*, const vector<InstructionTextToken>& prefix,
        size_t width, vector<pair<Type*, size_t>>&) override;

    static void Register();
};