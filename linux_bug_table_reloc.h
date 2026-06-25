#pragma once
#include <cstdint>

// Synthetic relocation type applied by ElfView::ParseLinuxKernelBugTable() to
// every WARN_ON brk/ud2 site found in the Linux kernel's __bug_table section.
//
// When Arm64ElfRelocationHandler / x64ElfRelocationHandler see this nativeType
// in ApplyRelocation they overwrite the instruction bytes with an architecture
// NOP, so the arch's GetInstructionInfo and GetInstructionLowLevelIL naturally
// produce fallthrough semantics — no ArchitectureHook required.
//
// The value is deliberately in a range unreachable by any real ELF R_* type
// (all known constants fit in 16-bit unsigned; this has the top bit of uint64
// set) so there is no collision risk.
static constexpr uint64_t LINUX_BUG_TABLE_WARN_NOP_RELOC = 0x8000000000000001ULL;
