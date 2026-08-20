#pragma once

#include "binaryninjaapi.h"


class GenericLineFormatter: public BinaryNinja::LineFormatter
{
public:
    GenericLineFormatter();

    std::vector<BinaryNinja::DisassemblyTextLine> FormatLines(
        const std::vector<BinaryNinja::DisassemblyTextLine>& lines,
		const BinaryNinja::LineFormatterSettings& settings) override;
};
