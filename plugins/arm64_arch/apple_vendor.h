// Copyright (c) 2026 Vector 35 Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#pragma once

#include <optional>
#include <stdint.h>
#include <string>
#include <vector>

#include "binaryninjaapi.h"
#include "neon_intrinsics.h"  // for ARM64_INTRIN_NEON_END

// Apple vendor-specific AArch64 instructions occupy the 0x0020xxxx encoding space (bits [31:16] ==
// 0x0020), which is unallocated in the base ARM A64 instruction set. They appear in Apple firmware
// such as the iOS kernelcache and SPTM. This module decodes, renders, and lifts them independently
// of the generated ARM disassembler, so no generated file or ARM spec data is touched.
//
// Encodings follow the AsahiLinux reverse-engineering documentation
// (https://asahilinux.org/docs/hw/cpu/apple-instructions/).

// Vendor intrinsic IDs begin immediately after the base ARM64 intrinsic range (NEON included) so
// they never collide with the base architecture's intrinsics. They are session-local (IL is
// regenerated per session and intrinsic IDs are not persisted).
enum AppleVendorIntrinsic : uint32_t
{
	APPLE_INTRIN_GENTER = ARM64_INTRIN_NEON_END + 1,
	APPLE_INTRIN_GEXIT,
	APPLE_INTRIN_SDSB,
	APPLE_INTRIN_WKDMC,
	APPLE_INTRIN_WKDMD,
	APPLE_INTRIN_AT_AS1ELX,
	APPLE_INTRIN_MUL53LO,
	APPLE_INTRIN_MUL53HI,
	APPLE_INTRIN_END,
};

// True if the instruction word might be an Apple vendor instruction. Most live in the 0x0020xxxx
// space (bits [31:16] == 0x0020), but at least one occupies the exception-generation encoding class
// in the opc == 0b111 slot (0xd4e0_0000) that ARM leaves unallocated.
// This is only a cheap pre-filter. The decoder makes the precise determination.
inline bool IsAppleVendorEncoding(uint32_t insn)
{
	return (insn & 0xffff0000) == 0x00200000 || (insn & 0xffe00000) == 0xd4e00000;
}

// The info and text paths return false if the word is not a recognized Apple vendor instruction. On
// success the info path sets result.length to 4.
bool AppleVendorGetInstructionInfo(uint32_t insn, uint64_t addr, BinaryNinja::InstructionInfo& result);
bool AppleVendorGetInstructionText(uint32_t insn, std::vector<BinaryNinja::InstructionTextToken>& result);
// Returns nullopt if the word is not a recognized Apple vendor instruction. Otherwise the contained
// value is what Architecture::GetInstructionLowLevelIL should return: true if the block continues past
// this instruction, false if it ends the block.
std::optional<bool> AppleVendorGetInstructionLowLevelIL(uint32_t insn, BinaryNinja::LowLevelILFunction& il);

// Metadata for vendor intrinsics.
bool AppleVendorIsIntrinsic(uint32_t intrinsic);
void AppleVendorGetAllIntrinsics(std::vector<uint32_t>& result);
std::string AppleVendorGetIntrinsicName(uint32_t intrinsic);
BNIntrinsicClass AppleVendorGetIntrinsicClass(uint32_t intrinsic);
std::vector<BinaryNinja::NameAndType> AppleVendorGetIntrinsicInputs(uint32_t intrinsic);
std::vector<BinaryNinja::Confidence<BinaryNinja::Ref<BinaryNinja::Type>>> AppleVendorGetIntrinsicOutputs(
    uint32_t intrinsic);
