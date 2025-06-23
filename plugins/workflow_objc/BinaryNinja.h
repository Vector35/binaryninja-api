/*
 * Copyright (c) 2022-2023 Jon Palmisciano. All rights reserved.
 *
 * Use of this source code is governed by the BSD 3-Clause license; the full
 * terms of the license can be found in the LICENSE.txt file.
 */

#pragma once

#include <binaryninjaapi.h>

using AnalysisContextRef = BinaryNinja::Ref<BinaryNinja::AnalysisContext>;
using BinaryViewRef = BinaryNinja::Ref<BinaryNinja::BinaryView>;
using LLILFunctionRef = BinaryNinja::Ref<BinaryNinja::LowLevelILFunction>;
using SymbolRef = BinaryNinja::Ref<BinaryNinja::Symbol>;
using TypeRef = BinaryNinja::Ref<BinaryNinja::Type>;

using BinaryViewPtr = BinaryNinja::BinaryView*;
using TypePtr = BinaryNinja::Type*;

using BinaryViewID = std::size_t;
