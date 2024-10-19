#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"

using namespace BinaryNinja;
using namespace std;


class WindowsX86Platform: public Platform
{
	uint32_t m_fsbase;
	Ref<Type> m_teb;

public:
	WindowsX86Platform(Architecture* arch): Platform(arch, "windows-x86")
	{
		Ref<CallingConvention> cc;

		m_fsbase = arch->GetRegisterByName("fsbase");

		cc = arch->GetCallingConventionByName("cdecl");
		if (cc)
		{
			RegisterDefaultCallingConvention(cc);
			RegisterCdeclCallingConvention(cc);
		}

		cc = arch->GetCallingConventionByName("fastcall");
		if (cc)
			RegisterFastcallCallingConvention(cc);

		cc = arch->GetCallingConventionByName("stdcall");
		if (cc)
			RegisterStdcallCallingConvention(cc);

		cc = arch->GetCallingConventionByName("thiscall");
		if (cc)
			RegisterCallingConvention(cc);

		// Linux-style register convention is commonly used by Borland compilers
		cc = arch->GetCallingConventionByName("regparm");
		if (cc)
			RegisterCallingConvention(cc);
	}


	virtual void BinaryViewInit(BinaryView* view) override
	{
		if (!m_teb)
			m_teb = Type::PointerType(GetArchitecture()->GetAddressSize(), Type::NamedType(QualifiedName("TEB"), GetTypeByName(QualifiedName("TEB"))));
	}


	virtual Ref<Type> GetGlobalRegisterType(uint32_t reg) override
	{
		if (reg == m_fsbase)
			return m_teb;

		return nullptr;
	}

	virtual void AdjustTypeParserInput(
		Ref<TypeParser> parser,
		std::vector<std::string>& arguments,
		std::vector<std::pair<std::string, std::string>>& sourceFiles
	) override
	{
		if (parser->GetName() != "ClangTypeParser")
		{
			return;
		}

		for (auto& arg: arguments)
		{
			if (arg.find("--target=") == 0 && arg.find("-unknown-") != std::string::npos)
			{
				arg = "--target=i386-pc-windows-msvc";
			}
		}
	}

	virtual bool GetFallbackEnabled() override
	{
		return false;
	}
};


class WindowsX64Platform: public Platform
{
	uint32_t m_gsbase;
	Ref<Type> m_teb;

public:
	WindowsX64Platform(Architecture* arch): Platform(arch, "windows-x86_64")
	{
		m_gsbase = arch->GetRegisterByName("gsbase");

		Ref<CallingConvention> cc;

		cc = arch->GetCallingConventionByName("win64");
		if (cc)
		{
			RegisterDefaultCallingConvention(cc);
			RegisterCdeclCallingConvention(cc);
			RegisterFastcallCallingConvention(cc);
			RegisterStdcallCallingConvention(cc);
		}
	}


	virtual void BinaryViewInit(BinaryView* view) override
	{
		if (!m_teb)
			m_teb = Type::PointerType(GetArchitecture()->GetAddressSize(), Type::NamedType(QualifiedName("TEB"), GetTypeByName(QualifiedName("TEB"))));
	}


	virtual Ref<Type> GetGlobalRegisterType(uint32_t reg) override
	{
		if (reg == m_gsbase)
			return m_teb;

		return nullptr;
	}

	virtual void AdjustTypeParserInput(
		Ref<TypeParser> parser,
		std::vector<std::string>& arguments,
		std::vector<std::pair<std::string, std::string>>& sourceFiles
	) override
	{
		if (parser->GetName() != "ClangTypeParser")
		{
			return;
		}

		for (auto& arg: arguments)
		{
			if (arg.find("--target=") == 0 && arg.find("-unknown-") != std::string::npos)
			{
				arg = "--target=x86_64-pc-windows-msvc";
			}
		}
	}

	virtual bool GetFallbackEnabled() override
	{
		return false;
	}
};


class WindowsArmv7Platform: public Platform
{
public:
	WindowsArmv7Platform(Architecture* arch, const std::string& name): Platform(arch, name)
	{
		Ref<CallingConvention> cc;

		cc = arch->GetCallingConventionByName("cdecl");
		if (cc)
		{
			RegisterDefaultCallingConvention(cc);
			RegisterCdeclCallingConvention(cc);
			RegisterFastcallCallingConvention(cc);
			RegisterStdcallCallingConvention(cc);
		}
	}

	virtual void AdjustTypeParserInput(
		Ref<TypeParser> parser,
		std::vector<std::string>& arguments,
		std::vector<std::pair<std::string, std::string>>& sourceFiles
	) override
	{
		if (parser->GetName() != "ClangTypeParser")
		{
			return;
		}

		for (auto& arg: arguments)
		{
			if (arg.find("--target=") == 0 && arg.find("-unknown-") != std::string::npos)
			{
				arg = "--target=armv7-pc-windows-msvc";
			}
		}
	}

	virtual bool GetFallbackEnabled() override
	{
		return false;
	}
};


class WindowsArm64Platform: public Platform
{
public:
	WindowsArm64Platform(Architecture* arch): Platform(arch, "windows-aarch64")
	{
		Ref<CallingConvention> cc;

		cc = arch->GetCallingConventionByName("cdecl");
		if (cc)
		{
			RegisterDefaultCallingConvention(cc);
			RegisterCdeclCallingConvention(cc);
			RegisterFastcallCallingConvention(cc);
			RegisterStdcallCallingConvention(cc);
		}

		/* "windows-syscall" is defined and registered in arch-arm64 */
		cc = arch->GetCallingConventionByName("windows-syscall");
		if (cc)
		{
			SetSystemCallConvention(cc);
		}
	}

	virtual void AdjustTypeParserInput(
		Ref<TypeParser> parser,
		std::vector<std::string>& arguments,
		std::vector<std::pair<std::string, std::string>>& sourceFiles
	) override
	{
		if (parser->GetName() != "ClangTypeParser")
		{
			return;
		}

		for (auto& arg: arguments)
		{
			if (arg.find("--target=") == 0 && arg.find("-unknown-") != std::string::npos)
			{
				arg = "--target=aarch64-pc-windows-msvc";
			}
		}
	}

	virtual bool GetFallbackEnabled() override
	{
		return false;
	}
};


class ExceptionHandlerPrologFunctionRecognizer : public FunctionRecognizer
{
	Ref<Platform> m_platform;
	uint32_t m_esp, m_ebp, m_fsbase;

public:
	ExceptionHandlerPrologFunctionRecognizer(Ref<Platform> platform) : m_platform(platform)
	{
		m_esp = platform->GetArchitecture()->GetRegisterByName("esp");
		m_ebp = platform->GetArchitecture()->GetRegisterByName("ebp");
		m_fsbase = platform->GetArchitecture()->GetRegisterByName("fsbase");
	}

	virtual bool RecognizeLowLevelIL(BinaryView* view, Function* func, LowLevelILFunction* il) override
	{
		// Make sure the function belongs to the desired platform. Platform specific function recognizers
		// are not a feature so this was registered for the architecture as a whole.
		if (func->GetPlatform() != m_platform)
			return false;

		// If inlining is already too high confidence, don't check as we won't override it.
		if (func->IsInlinedDuringAnalysis().GetConfidence() >= BN_HEURISTIC_CONFIDENCE)
			return false;

		// Iterate through the IL instructions and maintain a set of flags on whether this looks
		// like a shared function prolog.
		bool writesToExceptionFramePointer = false;
		bool writesToFramePointer = false;
		bool writesToStackPointer = false;
		bool pushesToStack = false;
		bool lastPushIsReturnAddr = false;
		bool writesToOldReturnAddr = false;
		uint32_t returnAddrReg = BN_INVALID_REGISTER;
		for (size_t i = 0; i < il->GetInstructionCount(); i++)
		{
			LowLevelILInstruction instr = il->GetInstruction(i);
			if (instr.operation == LLIL_RET)
				break;
			switch (instr.operation)
			{
			case LLIL_PUSH:
				pushesToStack = true;

				// If pushing again after pushing the return address, this is not a match.
				if (lastPushIsReturnAddr)
					return false;

				// Check for push of the return address, this should be the last push. It may come from a
				// previously stored register or loaded directly.
				if (returnAddrReg != BN_INVALID_REGISTER && instr.GetSourceExpr<LLIL_PUSH>().operation == LLIL_REG
					&& instr.GetSourceExpr<LLIL_PUSH>().GetSourceRegister<LLIL_REG>() == returnAddrReg)
				{
					lastPushIsReturnAddr = true;
				}
				else if (instr.GetSourceExpr<LLIL_PUSH>().operation == LLIL_LOAD)
				{
					RegisterValue addr = instr.GetSourceExpr<LLIL_PUSH>().GetSourceExpr<LLIL_LOAD>().GetValue();
					if (addr.state == StackFrameOffset && addr.value == 0)
					{
						// If the return address has already been overwritten, this is not a match.
						if (writesToOldReturnAddr)
							return false;
						lastPushIsReturnAddr = true;
					}
				}
				break;
			case LLIL_POP:
				// Should never see a pop, only pushes.
				return false;
			case LLIL_SET_REG:
				if (instr.GetSourceExpr<LLIL_SET_REG>().operation == LLIL_POP)
				{
					// Should never see a pop, only pushes.
					return false;
				}
				else if (instr.GetDestRegister() == m_ebp)
				{
					// Should always see a frame pointer being set up, should be pointing at a known
					// stack offset and there should be only one write.
					if (writesToFramePointer)
						return false;
					if (instr.GetSourceExpr<LLIL_SET_REG>().GetValue().state != StackFrameOffset)
						return false;
					writesToFramePointer = true;
				}
				else if (instr.GetDestRegister() == m_esp)
				{
					// There should only be one write to the stack pointer if it is a subtraction with
					// an unknown value (the incoming amount of stack space to allocate).
					if (writesToStackPointer)
						return false;
					if (instr.GetSourceExpr<LLIL_SET_REG>().operation != LLIL_SUB)
						return false;
					if (instr.GetSourceExpr<LLIL_SET_REG>().GetLeftExpr<LLIL_SUB>().operation != LLIL_REG)
						return false;
					if (instr.GetSourceExpr<LLIL_SET_REG>().GetLeftExpr<LLIL_SUB>().GetSourceRegister<LLIL_REG>()
						!= m_esp)
						return false;
					if (instr.GetSourceExpr<LLIL_SET_REG>().GetRightExpr<LLIL_SUB>().GetValue().state
						!= UndeterminedValue)
						return false;
					writesToStackPointer = true;
				}
				else if (instr.GetSourceExpr<LLIL_SET_REG>().operation == LLIL_LOAD)
				{
					// Read from memory, check for a read of the return address
					RegisterValue addr = instr.GetSourceExpr<LLIL_SET_REG>().GetSourceExpr<LLIL_LOAD>().GetValue();
					if (addr.state != StackFrameOffset || addr.value != 0)
						break;

					// There should only be one read. Keep track of which register holds it.
					if (returnAddrReg != BN_INVALID_REGISTER)
						return false;
					returnAddrReg = instr.GetDestRegister<LLIL_SET_REG>();
				}
				else if (instr.GetDestRegister<LLIL_SET_REG>() == returnAddrReg)
				{
					// If register that held return address is clobbered, remember that.
					returnAddrReg = BN_INVALID_REGISTER;
				}
				break;
			case LLIL_STORE:
				if (instr.GetDestExpr<LLIL_STORE>().operation == LLIL_REG
					&& instr.GetDestExpr<LLIL_STORE>().GetSourceRegister<LLIL_REG>() == m_fsbase)
				{
					// Writing to exception handler pointer, there should only be one of these.
					if (writesToExceptionFramePointer)
						return false;
					writesToExceptionFramePointer = true;
				}
				else if (instr.GetSourceExpr<LLIL_STORE>().operation == LLIL_POP)
				{
					// Should never see a pop, only pushes.
					return false;
				}
				else
				{
					// Check for writes to old return address. There should be only one of these.
					RegisterValue addr = instr.GetDestExpr<LLIL_STORE>().GetValue();
					if (addr.state != StackFrameOffset || addr.value != 0)
						break;
					if (writesToOldReturnAddr)
						return false;
					writesToOldReturnAddr = true;
				}
				break;
			case LLIL_JUMP:
			case LLIL_GOTO:
			case LLIL_IF:
			case LLIL_JUMP_TO:
			case LLIL_NORET:
				// Prolog functions are a single basic block, so this isn't one.
				return false;
			case LLIL_CALL:
			case LLIL_CALL_STACK_ADJUST:
			case LLIL_TAILCALL:
			case LLIL_SYSCALL:
				// Prolog functions are leaf functions.
				return false;
			case LLIL_UNDEF:
			case LLIL_UNIMPL:
			case LLIL_UNIMPL_MEM:
			case LLIL_BP:
			case LLIL_TRAP:
				// Prolog functions should not have unimplemented instructions or exceptions.
				return false;
			case LLIL_SET_REG_SPLIT:
			case LLIL_SET_FLAG:
			case LLIL_SET_REG_STACK_REL:
			case LLIL_REG_STACK_PUSH:
				// Prolog functions shouldn't have any split or float register stack manipluation.
				return false;
			default:
				break;
			}
		}

		if (!writesToExceptionFramePointer || !writesToFramePointer || !pushesToStack || !lastPushIsReturnAddr
			|| !writesToOldReturnAddr)
			return false;

		// Function satisfies constraints and looks like a shared prolog function. Mark it for inlining.
		func->SetAutoInlinedDuringAnalysis(Confidence<bool>(true, BN_HEURISTIC_CONFIDENCE));
		return true;
	}
};


class ExceptionHandlerEpilogFunctionRecognizer : public FunctionRecognizer
{
	Ref<Platform> m_platform;
	uint32_t m_esp, m_ebp, m_fsbase;

public:
	ExceptionHandlerEpilogFunctionRecognizer(Ref<Platform> platform) : m_platform(platform)
	{
		m_esp = platform->GetArchitecture()->GetRegisterByName("esp");
		m_ebp = platform->GetArchitecture()->GetRegisterByName("ebp");
		m_fsbase = platform->GetArchitecture()->GetRegisterByName("fsbase");
	}

	virtual bool RecognizeLowLevelIL(BinaryView* view, Function* func, LowLevelILFunction* il) override
	{
		// Make sure the function belongs to the desired platform. Platform specific function recognizers
		// are not a feature so this was registered for the architecture as a whole.
		if (func->GetPlatform() != m_platform)
			return false;

		// If inlining is already too high confidence, don't check as we won't override it.
		if (func->IsInlinedDuringAnalysis().GetConfidence() >= BN_HEURISTIC_CONFIDENCE)
			return false;

		// Iterate through the IL instructions and maintain a set of flags on whether this looks
		// like a shared function epilog.
		bool writesToExceptionFramePointer = false;
		bool restoresStackPointer = false;
		bool popsFromStack = false;
		bool lastPushBeforeReturn = false;
		bool stackCookieXor = false;
		bool stackCookieVerifyCall = false;
		for (size_t i = 0; i < il->GetInstructionCount(); i++)
		{
			LowLevelILInstruction instr = il->GetInstruction(i);
			if (instr.operation == LLIL_RET)
				break;
			switch (instr.operation)
			{
			case LLIL_PUSH:
				// There should be exactly one push instruction right before the return (this
				// is the return address, though we can't verify that since the frame pointer
				// is unknown for the analysis engine).
				if (lastPushBeforeReturn)
					return false;
				lastPushBeforeReturn = true;
				break;
			case LLIL_POP:
				// Should never see a standalone pop.
				return false;
			case LLIL_SET_REG:
				if (instr.GetSourceExpr<LLIL_SET_REG>().operation == LLIL_POP)
				{
					// Should see only pops before the last push
					if (lastPushBeforeReturn)
						return false;
					popsFromStack = true;
					break;
				}
				else if (instr.GetDestRegister() == m_ebp)
				{
					// Should not write to frame pointer until stack pointer is restored
					if (!restoresStackPointer)
						return false;
				}
				else if (instr.GetDestRegister() == m_esp)
				{
					// Ensure that this is a frame pointer restore. There should only be one of these.
					if (instr.GetSourceExpr<LLIL_SET_REG>().operation != LLIL_REG
						|| instr.GetSourceExpr<LLIL_SET_REG>().GetSourceRegister<LLIL_REG>() != m_ebp)
						return false;
					if (restoresStackPointer)
						return false;
					restoresStackPointer = true;
				}
				else if (instr.GetSourceExpr<LLIL_SET_REG>().operation == LLIL_XOR)
				{
					// Look for stack cookie transformations. There should only be one of these, and it
					// should be before any of the other actions.
					if (stackCookieXor || writesToExceptionFramePointer || restoresStackPointer || popsFromStack
						|| lastPushBeforeReturn)
						return false;
					stackCookieXor = true;
				}
				break;
			case LLIL_STORE:
				if (instr.GetDestExpr<LLIL_STORE>().operation == LLIL_REG
					&& instr.GetDestExpr<LLIL_STORE>().GetSourceRegister<LLIL_REG>() == m_fsbase)
				{
					// Writing to exception handler pointer, there should only be one of these.
					if (writesToExceptionFramePointer)
						return false;
					writesToExceptionFramePointer = true;
				}
				else if (instr.GetSourceExpr<LLIL_STORE>().operation == LLIL_POP)
				{
					// Should never see a pop to memory, only to registers.
					return false;
				}
				break;
			case LLIL_JUMP:
			case LLIL_IF:
			case LLIL_JUMP_TO:
			case LLIL_NORET:
				// Epilog functions are a single basic block, so this isn't one.
				return false;
			case LLIL_GOTO:
				// If there is a goto instruction, it must be to the next instruction (this will happen
				// when inlining other parts of the epilog).
				if (instr.GetTarget() != (instr.instructionIndex + 1))
					return false;
				break;
			case LLIL_CALL:
				// Epilog functions are either leaf functions or contain a single call to a stack cookie
				// verification function. Check for the stack cookie verification, which will be a call
				// to a static location just after the cookie transformation, and before any other actions.
				// There should be only one of these.
				if (instr.GetDestExpr<LLIL_CALL>().operation != LLIL_CONST
					&& instr.GetDestExpr<LLIL_CALL>().operation != LLIL_CONST_PTR)
					return false;
				if (!stackCookieXor || stackCookieVerifyCall || writesToExceptionFramePointer || restoresStackPointer
					|| popsFromStack || lastPushBeforeReturn)
					return false;
				stackCookieVerifyCall = true;
				break;
			case LLIL_CALL_STACK_ADJUST:
			case LLIL_TAILCALL:
			case LLIL_SYSCALL:
				// Epilog functions should not contain tailcalls, syscalls, or calls that adjust the stack.
				return false;
			case LLIL_UNDEF:
			case LLIL_UNIMPL:
			case LLIL_UNIMPL_MEM:
			case LLIL_BP:
			case LLIL_TRAP:
				// Epilog functions should not have unimplemented instructions or exceptions.
				return false;
			case LLIL_SET_REG_SPLIT:
			case LLIL_SET_FLAG:
			case LLIL_SET_REG_STACK_REL:
			case LLIL_REG_STACK_PUSH:
				// Epilog functions shouldn't have any split or float register stack manipluation.
				return false;
			default:
				break;
			}
		}

		if (!writesToExceptionFramePointer || !restoresStackPointer || !popsFromStack || !lastPushBeforeReturn)
			return false;

		// Function satisfies constraints and looks like a shared epilog function. Mark it for inlining.
		func->SetAutoInlinedDuringAnalysis(Confidence<bool>(true, BN_HEURISTIC_CONFIDENCE));
		return true;
	}
};


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifndef DEMO_EDITION
	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		AddOptionalPluginDependency("arch_x86");
		AddOptionalPluginDependency("arch_armv7");
		AddOptionalPluginDependency("arch_arm64");
		AddOptionalPluginDependency("view_pe");
	}
#endif

#ifdef DEMO_EDITION
	bool WindowsPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		Ref<Architecture> x86 = Architecture::GetByName("x86");
		Ref<Platform> windowsX86;
		if (x86)
		{
			windowsX86 = new WindowsX86Platform(x86);
			Platform::Register("windows", windowsX86);
			BinaryViewType::RegisterDefaultPlatform("PE", x86, windowsX86);
			BinaryViewType::RegisterDefaultPlatform("COFF", x86, windowsX86);
		}

		Ref<Architecture> x64 = Architecture::GetByName("x86_64");
		if (x64)
		{
			Ref<Platform> platform;

			platform = new WindowsX64Platform(x64);
			Platform::Register("windows", platform);
			BinaryViewType::RegisterDefaultPlatform("PE", x64, platform);
			BinaryViewType::RegisterDefaultPlatform("COFF", x64, platform);
		}

		Ref<Architecture> armv7 = Architecture::GetByName("armv7");
		Ref<Architecture> thumb2 = Architecture::GetByName("thumb2");
		if (armv7 && thumb2)
		{
			Ref<Platform> armPlatform, thumbPlatform;

			armPlatform = new WindowsArmv7Platform(armv7, "windows-armv7");
			thumbPlatform = new WindowsArmv7Platform(thumb2, "windows-thumb2");
			armPlatform->AddRelatedPlatform(thumb2, thumbPlatform);
			thumbPlatform->AddRelatedPlatform(armv7, armPlatform);
			Platform::Register("windows", armPlatform);
			Platform::Register("windows", thumbPlatform);
			BinaryViewType::RegisterDefaultPlatform("PE", armv7, armPlatform);
			BinaryViewType::RegisterDefaultPlatform("COFF", armv7, armPlatform);
			BinaryViewType::RegisterDefaultPlatform("COFF", thumb2, thumbPlatform);
		}

		Ref<Architecture> arm64 = Architecture::GetByName("aarch64");
		if (arm64)
		{
			Ref<Platform> platform;

			platform = new WindowsArm64Platform(arm64);
			Platform::Register("windows", platform);
			BinaryViewType::RegisterDefaultPlatform("PE", arm64, platform);
			BinaryViewType::RegisterDefaultPlatform("COFF", arm64, platform);
		}

		if (x86 && windowsX86)
		{
			// Set up exception handler prolog/epilog function inlining. These are registered for
			// the entire architecture but internally they check to make sure it is the Windows
			// platform. Internal implementation details prevent platform-specific function
			// recognizers from being registered.
			FunctionRecognizer::RegisterArchitectureFunctionRecognizer(
				x86, new ExceptionHandlerPrologFunctionRecognizer(windowsX86));
			FunctionRecognizer::RegisterArchitectureFunctionRecognizer(
				x86, new ExceptionHandlerEpilogFunctionRecognizer(windowsX86));
		}

		return true;
	}
}
