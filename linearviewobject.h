#pragma once
#include "binaryninja_defs.h"

extern "C" {
	struct BNLinearDisassemblyLine;
	BINARYNINJACOREAPI void BNFreeLinearDisassemblyLines(BNLinearDisassemblyLine* lines, size_t count);
}