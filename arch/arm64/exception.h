#pragma once

#include "binaryninjaapi.h"

namespace Arm64Exception
{
	enum Kind : uint32_t { Svc = 1, Hvc = 2, Smc = 3, Breakpoint = 4 };
	constexpr uint64_t KindMask = 0xffffffff00000000ULL;
	constexpr uint64_t Encode(Kind kind, uint32_t immediate = 0)
	{
		return (uint64_t(kind) << 32) | immediate;
	}

	inline void RegisterDefaults(BinaryNinja::Platform* platform)
	{
		for (auto [kind, name] : {std::pair{Svc, "svc"}, {Hvc, "hvc"}, {Smc, "smc"}, {Breakpoint, "brk"}})
			platform->SetExceptionDisplay({Encode(kind), KindMask, {name, 0xffffffffULL, 0}});
		platform->SetExceptionModel({Encode(Svc), KindMask,
			{TrapExceptionModel, 0, ContinueAfterException}});
		platform->SetExceptionModel({Encode(Hvc), KindMask,
			{TrapExceptionModel, 0, ContinueAfterException}});
		platform->SetExceptionModel({Encode(Smc), KindMask,
			{TrapExceptionModel, 0, ContinueAfterException}});
		// Even immediate zero does not establish an ABI. Platforms must explicitly
		// select SMCCC (or a different convention) when the execution environment is known.
		platform->SetExceptionModel({Encode(Breakpoint), KindMask,
			{BreakpointExceptionModel, 0, TerminateAfterException}});
	}

	inline void RegisterSvc(BinaryNinja::Platform* platform)
	{
		platform->SetExceptionModel({Encode(Svc), KindMask,
			{SystemCallExceptionModel, 0, ContinueAfterException}});
		platform->SetExceptionDisplay({Encode(Svc), UINT64_MAX, {"syscall", 0xffffULL, 0}});
	}
}
