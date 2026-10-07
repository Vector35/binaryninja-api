#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"

using namespace BinaryNinja;
using namespace std;

namespace
{
	// A small affine domain for the i386 process stack. argv is sp + 4 and
	// envp is sp + 4 * argc + 8. Keep these origins rather than using the
	// recovered callee prototype, which can omit unused main parameters.
	struct StartupValue
	{
		uint32_t stack = 0, argc = 0, constant = 0;
		bool operator==(const StartupValue&) const = default;
	};

	class FreeBSDCRTRecognizer : public FunctionRecognizer
	{
		struct RegisterStartup
		{
			// FreeBSD 14.x CRT layouts: lib/csu/{amd64,aarch64,arm,riscv,powerpc64}.
			// https://github.com/freebsd/freebsd-src/tree/releng/14.3/lib/csu
			size_t width;
			uint32_t packet;
			vector<uint32_t> arguments;
			bool wrapper;
		};

		struct RegisterStartupValue
		{
			uint64_t origin = 0, argc = 0, constant = 0;
			bool operator==(const RegisterStartupValue&) const = default;
		};

		static optional<RegisterStartupValue> IncomingRegister(const RegisterStartup& context, uint32_t reg)
		{
			if (context.wrapper)
			{
				if (reg == context.arguments[0])
					return RegisterStartupValue{0, 1, 0};
				if (reg == context.arguments[1])
					return RegisterStartupValue{1, 0, context.width};
				if (reg == context.arguments[2])
					return RegisterStartupValue{1, context.width, 2 * context.width};
			}
			else if (reg == context.packet)
				return RegisterStartupValue{1, 0, 0};
			return nullopt;
		}

		static optional<RegisterStartupValue> RegisterStartupRegister(LowLevelILFunction* ssa,
			const SSARegister& reg, const RegisterStartup& context, size_t depth, size_t& budget)
		{
			if (depth > 32 || !budget)
				return nullopt;
			budget--;
			if (reg.version == 0)
				return IncomingRegister(context, reg.reg);
			size_t definition = ssa->GetSSARegisterDefinition(reg);
			if (definition == BN_INVALID_EXPR)
				return nullopt;
			auto instruction = (*ssa)[definition];
			if (instruction.operation == LLIL_SET_REG_SSA)
				return RegisterStartupExpression(ssa, instruction.GetSourceExpr<LLIL_SET_REG_SSA>(), context, depth + 1, budget);
			if (instruction.operation == LLIL_REG_PHI)
			{
				optional<RegisterStartupValue> result;
				for (auto source : instruction.GetSourceSSARegisters<LLIL_REG_PHI>())
				{
					auto value = RegisterStartupRegister(ssa, source, context, depth + 1, budget);
					if (!value || (result && *result != *value))
						return nullopt;
					result = value;
				}
				return result;
			}
			return nullopt;
		}

		static optional<RegisterStartupValue> RegisterStartupExpression(LowLevelILFunction* ssa,
			const LowLevelILInstruction& expr, const RegisterStartup& context, size_t depth, size_t& budget)
		{
			if (depth > 32 || !budget || expr.size > context.width)
				return nullopt;
			budget--;
			if (expr.operation == LLIL_CONST || expr.operation == LLIL_CONST_PTR)
				return RegisterStartupValue{0, 0, (uint64_t)expr.GetConstant()};
			// ARM's argument block is the incoming stack. The other supported
			// architectures receive its address in rdi, x0, or a0 instead.
			if (!context.wrapper && context.packet == ssa->GetArchitecture()->GetStackPointerRegister())
			{
				if (auto value = expr.GetValue(); value.state == StackFrameOffset)
					return RegisterStartupValue{1, 0, (uint64_t)value.value};
			}
			if (auto value = expr.GetValue(); value.state == EntryValue)
			{
				if (auto incoming = IncomingRegister(context, (uint32_t)value.value))
				{
					if (expr.size == context.width || (!incoming->origin && expr.size >= 4))
						return incoming;
				}
			}
			switch (expr.operation)
			{
			case LLIL_REG_SSA:
			{
				auto value = RegisterStartupRegister(ssa, expr.GetSourceSSARegister<LLIL_REG_SSA>(), context, depth + 1, budget);
				return value && (!value->origin || expr.size == context.width) ? value : nullopt;
			}
			case LLIL_REG_SSA_PARTIAL:
			{
				auto value = RegisterStartupRegister(ssa, expr.GetSourceSSARegister<LLIL_REG_SSA_PARTIAL>(), context, depth + 1, budget);
				return value && !value->origin && expr.size >= 4 ? value : nullopt;
			}
			case LLIL_SX:
			case LLIL_ZX:
			case LLIL_LOW_PART:
			{
				auto value = RegisterStartupExpression(ssa, expr.GetSourceExpr(), context, depth + 1, budget);
				return value && !value->origin && expr.size >= 4 ? value : nullopt;
			}
			case LLIL_LOAD_SSA:
			{
				auto address = RegisterStartupExpression(ssa, expr.GetSourceExpr<LLIL_LOAD_SSA>(), context, depth + 1, budget);
				if (address && *address == RegisterStartupValue{1, 0, 0} && (expr.size == 4 || expr.size == context.width))
					return RegisterStartupValue{0, 1, 0};
				return nullopt;
			}
			case LLIL_ADD:
			case LLIL_SUB:
			case LLIL_MUL:
			case LLIL_LSL:
			{
				auto left = RegisterStartupExpression(ssa, expr.GetLeftExpr(), context, depth + 1, budget);
				auto right = RegisterStartupExpression(ssa, expr.GetRightExpr(), context, depth + 1, budget);
				if (!left || !right)
					return nullopt;
				if ((left->origin || right->origin) && expr.size != context.width)
					return nullopt;
				if (expr.operation == LLIL_ADD)
					return RegisterStartupValue{left->origin + right->origin, left->argc + right->argc, left->constant + right->constant};
				if (expr.operation == LLIL_SUB)
					return RegisterStartupValue{left->origin - right->origin, left->argc - right->argc, left->constant - right->constant};
				if (right->origin || right->argc || (expr.operation == LLIL_LSL && right->constant >= 64))
					return nullopt;
				uint64_t factor = expr.operation == LLIL_LSL ? uint64_t(1) << right->constant : right->constant;
				return RegisterStartupValue{left->origin * factor, left->argc * factor, left->constant * factor};
			}
			default:
				return nullopt;
			}
		}

		static map<size_t, LowLevelILInstruction> RegisterArguments(LowLevelILFunction* il, size_t call,
			const RegisterStartup& context)
		{
			map<size_t, LowLevelILInstruction> result;
			auto instruction = (*il)[call].GetSSAForm();
			if (instruction.operation != LLIL_CALL_SSA && instruction.operation != LLIL_TAILCALL_SSA)
				return result;
			LowLevelILInstructionList params = instruction.operation == LLIL_CALL_SSA ?
				instruction.GetParameterExprs<LLIL_CALL_SSA>() : instruction.GetParameterExprs<LLIL_TAILCALL_SSA>();
			for (auto param : params)
			{
				param.VisitExprs([&](const LowLevelILInstruction& expr) {
					if (expr.operation == LLIL_REG_SSA || expr.operation == LLIL_REG_SSA_PARTIAL)
					{
						auto reg = expr.operation == LLIL_REG_SSA ? expr.GetSourceSSARegister<LLIL_REG_SSA>() :
							expr.GetSourceSSARegister<LLIL_REG_SSA_PARTIAL>();
						for (size_t index = 0; index < context.arguments.size(); index++)
							if (reg.reg == context.arguments[index])
								result.emplace(index, expr);
						return false;
					}
					return true;
				});
			}
			// A recovered callee type may omit unused inputs. Also retain
			// the actual recent register writes, independent of inferred arity.
			auto block = il->GetBasicBlockForInstruction(call);
			set<size_t> written;
			for (size_t i = call; block && i > block->GetStart() && call - i < 64;)
			{
				auto write = (*il)[--i];
				if (write.operation == LLIL_CALL || write.operation == LLIL_TAILCALL)
					break;
				if (write.operation != LLIL_SET_REG)
					continue;
				uint32_t full = il->GetArchitecture()->GetRegisterInfo(write.GetDestRegister<LLIL_SET_REG>()).fullWidthRegister;
				auto definition = write.GetSSAForm();
				for (size_t index = 0; index < context.arguments.size(); index++)
					if (full == context.arguments[index] && !result.count(index) && written.insert(index).second)
						if (definition.operation == LLIL_SET_REG_SSA)
							result.emplace(index, definition.GetSourceExpr<LLIL_SET_REG_SSA>());
			}
			// ARM passes the fifth main-pointer argument on the stack. Read
			// actual writes, as in the i386 recognizer, rather than inferred arity.
			if (context.width == 4)
				for (auto& [slot, value] : Arguments(il, call))
					result.emplace(context.arguments.size() + slot, value);
			return result;
		}

		static bool RegisterInputsMatch(LowLevelILFunction* ssa, const map<size_t, LowLevelILInstruction>& args,
			const RegisterStartup& context)
		{
			const RegisterStartupValue expected[] = {{0, 1, 0}, {1, 0, context.width}, {1, context.width, 2 * context.width}};
			for (size_t index = 0; index < 3; index++)
			{
				auto item = args.find(index);
				if (item == args.end())
					return false;
				size_t budget = 256;
				auto value = RegisterStartupExpression(ssa, item->second, context, 0, budget);
				if (!value || *value != expected[index])
					return false;
			}
			return true;
		}

		static bool IsMainCallbackValue(LowLevelILFunction* ssa, const LowLevelILInstruction& expr,
			const RegisterStartup& context, size_t depth, size_t& budget)
		{
			if (depth > 32 || !budget || expr.size != context.width)
				return false;
			budget--;
			if (context.arguments.size() > 4)
			{
				auto value = expr.GetValue();
				if (value.state == EntryValue && value.value == context.arguments[4])
					return true;
			}
			if (expr.operation == LLIL_REG_SSA)
			{
				auto reg = expr.GetSourceSSARegister<LLIL_REG_SSA>();
				if (!reg.version)
					return context.arguments.size() > 4 && reg.reg == context.arguments[4];
				size_t definition = ssa->GetSSARegisterDefinition(reg);
				if (definition == BN_INVALID_EXPR)
					return false;
				auto instruction = (*ssa)[definition];
				return instruction.operation == LLIL_SET_REG_SSA &&
					IsMainCallbackValue(ssa, instruction.GetSourceExpr<LLIL_SET_REG_SSA>(), context, depth + 1, budget);
			}
			if (context.arguments.size() == 4 && expr.operation == LLIL_LOAD_SSA)
			{
				// ARM's fifth incoming argument is at stack offset zero: LR,
				// unlike x86's return address, is not pushed by the caller.
				auto address = expr.GetSourceExpr<LLIL_LOAD_SSA>().GetValue();
				return address.state == StackFrameOffset && address.value == 0;
			}
			return false;
		}

		static bool IsExitRoutine(BinaryView* view, Platform* platform, uint64_t address, size_t depth, size_t& budget)
		{
			if (depth > 3 || !budget)
				return false;
			if (auto symbol = view->GetSymbolByAddress(address); symbol &&
				(symbol->GetRawName() == "exit" || symbol->GetRawName() == "_exit"))
				return true;
			auto function = view->GetAnalysisFunction(platform, address);
			if (!function)
				return false;
			auto il = function->GetLowLevelIL();
			if (!il || il->GetInstructionCount() > budget)
				return false;
			budget -= il->GetInstructionCount();
			auto arch = function->GetArchitecture();
			const auto name = platform->GetName();
			uint32_t number = arch->GetRegisterByName(name == "freebsd-x86_64" ? "rax" :
				name == "freebsd-aarch64" ? "x8" : name == "freebsd-rv64gc" ? "t0" :
				name == "freebsd-ppc64_le" ? "r0" : "r7");
			for (size_t i = 0; i < il->GetInstructionCount(); i++)
				if (auto instruction = (*il)[i]; instruction.operation == LLIL_SYSCALL)
				{
					// SYS_exit is 1 on these FreeBSD ABIs. This also recognizes
					// stripped libc exit wrappers whose boundaries/noreturn type
					// have not yet been recovered in the caller.
					auto value = function->GetRegisterValueAtInstruction(arch, instruction.address, number);
					if (value.IsConstant() && value.value == 1)
						return true;
				}
			for (size_t i = 0; i < il->GetInstructionCount(); i++)
			{
				auto instruction = (*il)[i];
				if (instruction.operation != LLIL_CALL && instruction.operation != LLIL_TAILCALL)
					continue;
				auto target = instruction.GetDestExpr().GetValue();
				if (target.IsConstant() && IsExitRoutine(view, platform, target.value, depth + 1, budget))
					return true;
			}
			return false;
		}

		static bool HasMainCallback(BinaryView* view, Platform* platform, uint64_t address, RegisterStartup context)
		{
			// A fully stripped static libc has no __libc_start1 symbol. Require
			// its code to invoke the fifth argument with the first three inputs,
			// then forward that result to a terminal call. Initializers that merely
			// invoke a callback with the same arguments are not sufficient.
			auto function = view->GetAnalysisFunction(platform, address);
			if (!function)
				return false;
			auto il = function->GetLowLevelIL();
			if (!il || il->GetInstructionCount() > 4096)
				return false;
			auto ssa = il->GetSSAForm();
			if (!ssa)
				return false;
			context.wrapper = true;
			for (size_t i = 0; i < il->GetInstructionCount(); i++)
			{
				auto call = (*il)[i];
				if (call.operation != LLIL_CALL)
					continue;
				auto callSSA = call.GetSSAForm();
				if (callSSA.operation != LLIL_CALL_SSA)
					continue;
				size_t budget = 256;
				if (IsMainCallbackValue(ssa, callSSA.GetDestExpr<LLIL_CALL_SSA>(), context, 0, budget) &&
					RegisterInputsMatch(ssa, RegisterArguments(il, i, context), context))
				{
					auto block = il->GetBasicBlockForInstruction(i);
					for (size_t j = i + 1; block && j < block->GetEnd() && j <= i + 16; j++)
					{
						if ((*il)[j].operation != LLIL_CALL && (*il)[j].operation != LLIL_TAILCALL)
							continue;
						auto status = RegisterArguments(il, j, context);
						uint32_t resultRegister = platform->GetDefaultCallingConvention()->GetIntegerReturnValueRegister();
						bool forwarded = status.count(0) && IsMainResult(ssa, status.at(0),
							callSSA.instructionIndex, resultRegister, 0, context.width);
						if (!status.count(0) && resultRegister == context.arguments[0])
						{
							// A stripped callee's inferred prototype can omit even its
							// status argument. Prove the ABI result/argument register
							// survives unchanged instead of relying on that prototype.
							forwarded = true;
							for (size_t k = i + 1; k < j; k++)
							{
								auto move = (*il)[k];
								if (move.operation != LLIL_SET_REG || il->GetArchitecture()->GetRegisterInfo(
									move.GetDestRegister<LLIL_SET_REG>()).fullWidthRegister == resultRegister)
								{
									forwarded = false;
									break;
								}
							}
						}
						if (forwarded)
						{
							auto target = (*il)[j].GetDestExpr().GetValue();
							size_t exitBudget = 4096;
							if (IsTerminalCall(il, j) || (target.IsConstant() &&
								IsExitRoutine(view, platform, target.value, 0, exitBudget)))
								return true;
						}
						break;
					}
				}
			}
			return false;
		}

		static bool IsTerminalCall(LowLevelILFunction* il, size_t call)
		{
			if ((*il)[call].operation == LLIL_TAILCALL)
				return true;
			auto block = il->GetBasicBlockForInstruction(call);
			for (size_t i = call + 1; block && i < block->GetEnd() && i <= call + 4; i++)
			{
				auto next = (*il)[i];
				if (next.operation == LLIL_NORET || next.operation == LLIL_TRAP ||
					next.operation == LLIL_BP || next.operation == LLIL_UNDEF)
					return true;
				// PPC64 restores the caller's TOC after an indirect call, even
				// when the CRT immediately follows it with __builtin_unreachable.
				if (next.operation != LLIL_SET_REG ||
					il->GetArchitecture()->GetName() != "ppc64_le" ||
					next.GetDestRegister<LLIL_SET_REG>() != il->GetArchitecture()->GetRegisterByName("r2") ||
					next.GetSourceExpr<LLIL_SET_REG>().operation != LLIL_LOAD ||
					next.GetSourceExpr<LLIL_SET_REG>().GetSourceExpr<LLIL_LOAD>().GetValue().state != StackFrameOffset)
					return false;
			}
			return false;
		}

		static void ModelRegisterEntry(BinaryView* view, Platform* platform, const RegisterStartup& context)
		{
			uint64_t address = view->GetEntryPoint();
			auto entryPlatform = platform->GetAssociatedPlatformByAddress(address);
			auto entry = view->GetAnalysisFunction(entryPlatform, address);
			if (!entry || entry->QueryMetadata("__BN_has_stack_return_address"))
				return;
			entry->StoreMetadata("__BN_has_stack_return_address", new Metadata(false));
			if (!entry->HasUserType())
			{
				auto cc = entryPlatform->GetDefaultCallingConvention();
				auto pointer = Type::PointerType(context.width, Type::VoidType());
				auto cleanup = Type::PointerType(context.width, Type::FunctionType(Type::VoidType(),
					cc, {}));
				vector<FunctionParameter> params;
				if (context.width == 4)
				{
					auto argv0 = Type::PointerType(4, Type::IntegerType(1, true));
					entry->CreateAutoStackVariable(0, Type::IntegerType(4, true), "argc");
					entry->CreateAutoStackVariable(4, argv0, "argv0");
					params = {{"argc", Type::IntegerType(4, true), CustomLocationSource, Variable(StackVariableSourceType, 0, 0)},
						{"argv0", argv0, CustomLocationSource, Variable(StackVariableSourceType, 0, 4)},
						{"ps_strings", pointer, CustomLocationSource, Variable(RegisterVariableSourceType, 0, context.arguments[0])},
						{"object", pointer, CustomLocationSource, Variable(RegisterVariableSourceType, 0, context.arguments[1])},
						{"cleanup", cleanup, CustomLocationSource, Variable(RegisterVariableSourceType, 0, context.arguments[2])}};
				}
				else if (entryPlatform->GetName() == "freebsd-ppc64_le")
				{
					auto strings = Type::PointerType(context.width, Type::PointerType(context.width, Type::IntegerType(1, true)));
					params = {{"argc", Type::IntegerType(4, true), CustomLocationSource, Variable(RegisterVariableSourceType, 0, context.arguments[0])},
						{"argv", strings, CustomLocationSource, Variable(RegisterVariableSourceType, 0, context.arguments[1])},
						{"envp", strings, CustomLocationSource, Variable(RegisterVariableSourceType, 0, context.arguments[2])},
						{"object", pointer, CustomLocationSource, Variable(RegisterVariableSourceType, 0, context.arguments[3])},
						{"cleanup", cleanup, CustomLocationSource, Variable(RegisterVariableSourceType, 0, context.arguments[4])},
						{"ps_strings", pointer, CustomLocationSource, Variable(RegisterVariableSourceType, 0, context.arguments[5])}};
				}
				else
				{
					auto block = Type::PointerType(context.width, Type::IntegerType(context.width, false));
					uint32_t cleanupRegister = context.arguments[platform->GetName() == "freebsd-x86_64" ? 1 : 2];
					params = {{"argument_block", block, CustomLocationSource, Variable(RegisterVariableSourceType, 0, context.packet)},
						{"cleanup", cleanup, CustomLocationSource, Variable(RegisterVariableSourceType, 0, cleanupRegister)}};
				}
				entry->ApplyAutoDiscoveredType(Type::FunctionType(Type::VoidType(), cc,
					params, false, false, 0));
			}
			entry->Reanalyze();
		}

		static Ref<Symbol> CalledSymbol(BinaryView* view, LowLevelILFunction* ssa,
			const LowLevelILInstruction& expr, size_t depth, size_t& budget)
		{
			if (depth > 32 || !budget)
				return nullptr;
			budget--;
			auto value = expr.GetValue();
			if (value.IsConstant() || value.state == ImportedAddressValue)
				if (auto symbol = view->GetSymbolByAddress(value.value))
					return symbol;
			if (expr.operation == LLIL_REG_SSA)
			{
				size_t definition = ssa->GetSSARegisterDefinition(expr.GetSourceSSARegister<LLIL_REG_SSA>());
				if (definition == BN_INVALID_EXPR)
					return nullptr;
				auto copy = (*ssa)[definition];
				if (copy.operation == LLIL_SET_REG_SSA)
					return CalledSymbol(view, ssa, copy.GetSourceExpr<LLIL_SET_REG_SSA>(), depth + 1, budget);
			}
			if (expr.operation == LLIL_LOAD_SSA)
			{
				// The value of an unresolved import may be unknown, but the
				// relocation-backed slot still identifies which function is called.
				auto address = expr.GetSourceExpr<LLIL_LOAD_SSA>().GetValue();
				if (address.IsConstant())
				{
					if (auto symbol = view->GetSymbolByAddress(address.value); symbol && symbol->GetType() == ImportAddressSymbol)
						return symbol;
					// Some PPC64 CRTs use an absolute ADDR64 relocation in .toc
					// rather than GLOB_DAT. It has no import-address symbol at the
					// slot, but its explicit, full-width relocation names the import.
					for (auto relocation : view->GetRelocationsAt(address.value))
					{
						auto info = relocation->GetInfo();
						if (relocation->GetAddress() != address.value || info.type != StandardRelocationType ||
							!info.dataRelocation || info.size != expr.size || info.pcRelative ||
							info.implicitAddend || info.addend != 0)
							continue;
						if (auto symbol = relocation->GetSymbol(); symbol && symbol->GetType() == ExternalSymbol)
							return symbol;
					}
				}
			}
			return nullptr;
		}

		static bool RecognizeRegisterStartup(BinaryView* view, Function* function, LowLevelILFunction* il)
		{
			auto platform = function->GetPlatform();
			const auto name = platform->GetName();
			if (name != "freebsd-x86_64" && name != "freebsd-aarch64" && name != "freebsd-rv64gc" &&
				name != "freebsd-armv7" && name != "freebsd-thumb2" && name != "freebsd-ppc64_le")
				return false;
			auto arch = function->GetArchitecture();
			size_t width = view->GetAddressSize();
			bool arm = name == "freebsd-armv7" || name == "freebsd-thumb2";
			if (width != (arm ? 4 : 8))
				return false;
			auto cc = platform->GetDefaultCallingConvention();
			if (!cc)
				return false;
			auto registers = cc->GetIntegerArgumentRegisters();
			bool decoded = name == "freebsd-ppc64_le";
			if (registers.size() < (decoded ? 6 : 4))
				return false;
			bool entry = function->GetStart() == view->GetEntryPoint();
			auto wrapper = view->QueryMetadata("__BN_freebsd_register_startup");
			bool isWrapper = wrapper && wrapper->IsUnsignedInteger() && wrapper->GetUnsignedInteger() == function->GetStart();
			if ((!entry && !isWrapper) || view->QueryMetadata("__BN_main_function_address"))
				return false;
			// PowerPC's SVR4 entry ABI supplies argc/argv/envp in r3/r4/r5,
			// already decoded by the kernel, rather than an argument-block pointer.
			RegisterStartup context{width, arm ? arch->GetStackPointerRegister() : registers[0], registers, isWrapper || decoded};
			auto ssa = il->GetSSAForm();
			if (!ssa)
				return false;
			for (size_t i = 0; i < il->GetInstructionCount(); i++)
			{
				auto call = (*il)[i];
				if (call.operation != LLIL_CALL && call.operation != LLIL_TAILCALL)
					continue;
				auto target = call.GetDestExpr().GetValue();
				auto callSSA = call.GetSSAForm();
				if (callSSA.operation != LLIL_CALL_SSA && callSSA.operation != LLIL_TAILCALL_SSA)
					continue;
				size_t budget = 256;
				auto symbol = CalledSymbol(view, ssa, callSSA.GetDestExpr(), 0, budget);
				bool libcStart = symbol && (symbol->GetRawName() == "__libc_start1" || symbol->GetRawName() == "__libc_start1_gcrt");
				// PPC64 can call the imported function through its TOC/GOT slot,
				// without an executable PLT thunk at the relocation's address.
				if (!libcStart && (!target.IsConstant() || !view->IsOffsetExecutable(target.value)))
					continue;
				auto args = RegisterArguments(il, i, context);
				if (!RegisterInputsMatch(ssa, args, context))
					continue;
				bool terminal = IsTerminalCall(il, i);
				if (args.count(4) && (libcStart || (terminal && HasMainCallback(view, platform, target.value, context))))
				{
					auto main = args.at(4).GetValue();
					if (main.IsConstant() && PublishMain(view, function, main.value))
					{
						ModelRegisterEntry(view, platform, context);
						return true;
					}
				}
				if (entry && terminal && !libcStart && (!IsCRTUtility(symbol) || (symbol && symbol->GetRawName() == "__start")))
				{
					auto next = view->GetAnalysisFunction(platform, target.value);
					if (next && next != function)
					{
						if (!wrapper || !wrapper->IsUnsignedInteger() || wrapper->GetUnsignedInteger() != target.value)
						{
							view->StoreMetadata("__BN_freebsd_register_startup", new Metadata((uint64_t)target.value), MetadataStoreEphemeral);
							next->Reanalyze();
						}
					}
				}
			}
			return false;
		}

		static bool IsCRTUtility(Symbol* symbol)
		{
			if (!symbol)
				return false;
			static const set<string> names = {"_init", "_fini", "atexit", "_init_tls", "_start1",
				"exit", "_exit", "__libc_start1", "__libc_start1_gcrt"};
			return names.count(symbol->GetRawName()) != 0;
		}

		static optional<StartupValue> RegisterValue(LowLevelILFunction* ssa, const SSARegister& reg, bool wrapper,
			size_t depth, size_t& budget)
		{
			if (depth > 32 || !budget)
				return nullopt;
			budget--;
			size_t def = ssa->GetSSARegisterDefinition(reg);
			if (def == BN_INVALID_EXPR)
				return nullopt;
			auto instruction = (*ssa)[def];
			if (instruction.operation == LLIL_SET_REG_SSA)
				return Value(ssa, instruction.GetSourceExpr<LLIL_SET_REG_SSA>(), wrapper, depth + 1, budget);
			if (instruction.operation == LLIL_REG_PHI)
			{
				optional<StartupValue> result;
				for (auto source : instruction.GetSourceSSARegisters<LLIL_REG_PHI>())
				{
					auto value = RegisterValue(ssa, source, wrapper, depth + 1, budget);
					if (!value || (result && *result != *value))
						return nullopt;
					result = value;
				}
				return result;
			}
			return nullopt;
		}

		static optional<StartupValue> Value(LowLevelILFunction* ssa, const LowLevelILInstruction& expr,
			bool wrapper, size_t depth, size_t& budget)
		{
			if (depth > 32 || !budget)
				return nullopt;
			budget--;
			if ((expr.operation == LLIL_CONST || expr.operation == LLIL_CONST_PTR) && expr.size <= 4)
				return StartupValue{0, 0, (uint32_t)expr.GetConstant()};
			if (expr.size != 4)
				return nullopt;
			if (auto value = expr.GetValue(); value.state == StackFrameOffset)
				return StartupValue{1, 0, (uint32_t)value.value};
			switch (expr.operation)
			{
			case LLIL_REG_SSA:
				return RegisterValue(ssa, expr.GetSourceSSARegister<LLIL_REG_SSA>(), wrapper, depth + 1, budget);
			case LLIL_LOAD_SSA:
			{
				auto address = expr.GetSourceExpr<LLIL_LOAD_SSA>().GetValue();
				if (address.state != StackFrameOffset)
					return nullopt;
				if (address.value == (wrapper ? 8 : 0))
					return StartupValue{0, 1, 0};
				if (wrapper && address.value == 12)
					return StartupValue{1, 0, 4};
				return nullopt;
			}
			case LLIL_ADD:
			case LLIL_SUB:
			case LLIL_MUL:
			case LLIL_LSL:
			{
				auto left = Value(ssa, expr.GetLeftExpr(), wrapper, depth + 1, budget);
				auto right = Value(ssa, expr.GetRightExpr(), wrapper, depth + 1, budget);
				if (!left || !right)
					return nullopt;
				if (expr.operation == LLIL_ADD)
					return StartupValue{left->stack + right->stack, left->argc + right->argc, left->constant + right->constant};
				if (expr.operation == LLIL_SUB)
					return StartupValue{left->stack - right->stack, left->argc - right->argc, left->constant - right->constant};
				if (right->stack || right->argc)
					return nullopt;
				uint32_t factor = right->constant;
				if (expr.operation == LLIL_LSL)
				{
					if (factor >= 32)
						return nullopt;
					factor = 1u << factor;
				}
				return StartupValue{left->stack * factor, left->argc * factor, left->constant * factor};
			}
			default:
				return nullopt;
			}
		}

		static optional<int64_t> StackOffset(const LowLevelILInstruction& expr, uint32_t sp)
		{
			if (expr.operation == LLIL_REG && expr.GetSourceRegister<LLIL_REG>() == sp)
				return 0;
			if (expr.operation == LLIL_ADD || expr.operation == LLIL_SUB)
			{
				auto left = expr.GetLeftExpr(), right = expr.GetRightExpr();
				if (left.operation == LLIL_REG && left.GetSourceRegister<LLIL_REG>() == sp && right.operation == LLIL_CONST)
					return expr.operation == LLIL_ADD ? (int32_t)right.GetConstant() : -(int64_t)(int32_t)right.GetConstant();
			}
			return nullopt;
		}

		static map<size_t, LowLevelILInstruction> Arguments(LowLevelILFunction* il, size_t call)
		{
			map<size_t, LowLevelILInstruction> result;
			set<size_t> overwritten;
			auto block = il->GetBasicBlockForInstruction(call);
			if (!block)
				return result;
			uint32_t sp = il->GetArchitecture()->GetStackPointerRegister();
			int64_t delta = 0;
			// Read actual outgoing pushes/stores, independent of inferred arity.
			for (size_t i = call; i > block->GetStart() && call - i < 64;)
			{
				auto instruction = (*il)[--i];
				if (instruction.operation == LLIL_CALL || instruction.operation == LLIL_TAILCALL)
					break;
				optional<int64_t> offset;
				if (instruction.operation == LLIL_PUSH)
				{
					offset = delta;
					delta += instruction.size;
				}
				else if (instruction.operation == LLIL_STORE)
				{
					if (auto relative = StackOffset(instruction.GetDestExpr<LLIL_STORE>(), sp))
						offset = delta + *relative;
				}
				else if (instruction.operation == LLIL_SET_REG && instruction.GetDestRegister<LLIL_SET_REG>() == sp)
				{
					auto adjustment = StackOffset(instruction.GetSourceExpr<LLIL_SET_REG>(), sp);
					if (!adjustment)
						break;
					delta -= *adjustment;
				}
				if (offset)
				{
					for (size_t slot = 0; slot < 7; slot++)
					{
						int64_t start = (int64_t)slot * 4;
						if (*offset >= start + 4 || *offset + (int64_t)instruction.size <= start ||
							result.count(slot) || overwritten.count(slot))
							continue;
						auto ssa = instruction.GetSSAForm();
						if (*offset == start && instruction.size == 4 && ssa.operation == LLIL_STORE_SSA)
							result.emplace(slot, ssa.GetSourceExpr<LLIL_STORE_SSA>());
						else
							overwritten.insert(slot);
					}
				}
			}
			return result;
		}

		static bool Matches(LowLevelILFunction* ssa, const map<size_t, LowLevelILInstruction>& args,
			size_t index, const StartupValue& expected, bool wrapper)
		{
			auto item = args.find(index);
			if (item == args.end())
				return false;
			size_t budget = 256;
			auto value = Value(ssa, item->second, wrapper, 0, budget);
			return value && *value == expected;
		}

		static bool IsMainResult(LowLevelILFunction* ssa, const LowLevelILInstruction& value,
			size_t call, uint32_t resultRegister, size_t depth = 0, size_t width = 4)
		{
			if (width != 4 && depth <= 16 && (value.operation == LLIL_ZX || value.operation == LLIL_SX ||
				value.operation == LLIL_LOW_PART) && (value.size == 4 || value.size == width))
				return IsMainResult(ssa, value.GetSourceExpr(), call, resultRegister, depth + 1, width);
			if (depth > 16 || (value.operation != LLIL_REG_SSA && value.operation != LLIL_REG_SSA_PARTIAL) ||
				(value.size != 4 && value.size != width))
				return false;
			auto reg = value.operation == LLIL_REG_SSA ? value.GetSourceSSARegister<LLIL_REG_SSA>() :
				value.GetSourceSSARegister<LLIL_REG_SSA_PARTIAL>();
			size_t definition = ssa->GetSSARegisterDefinition(reg);
			if (definition == call)
				return reg.reg == resultRegister;
			if (definition == BN_INVALID_EXPR)
				return false;
			auto copy = (*ssa)[definition];
			return copy.operation == LLIL_SET_REG_SSA &&
				IsMainResult(ssa, copy.GetSourceExpr<LLIL_SET_REG_SSA>(), call, resultRegister, depth + 1, width);
		}

		static void ModelEntry(Function* function)
		{
			if (function->QueryMetadata("__BN_has_stack_return_address"))
				return;
			function->StoreMetadata("__BN_has_stack_return_address", new Metadata(false));
			auto platform = function->GetPlatform();
			auto character = Type::IntegerType(1, true);
			// Offset four contains argv[0], not an argv pointer. Its address is
			// the vector passed to main; an array-typed scalar load would produce
			// misleading array assignments in the reconstructed startup code.
			auto argv0 = Type::PointerType(4, character);
			auto cleanup = Type::PointerType(4, Type::FunctionType(Type::VoidType(), platform->GetDefaultCallingConvention(), {}));
			function->CreateAutoStackVariable(0, Type::IntegerType(4, true), "argc");
			function->CreateAutoStackVariable(4, argv0, "argv0");
			if (!function->HasUserType())
			{
				vector<FunctionParameter> params = {
					{"argc", Type::IntegerType(4, true), CustomLocationSource, Variable(StackVariableSourceType, 0, 0)},
					{"argv0", argv0, CustomLocationSource, Variable(StackVariableSourceType, 0, 4)},
					{"cleanup", cleanup, CustomLocationSource,
						Variable(RegisterVariableSourceType, 0, platform->GetArchitecture()->GetRegisterByName("edx"))}};
				function->ApplyAutoDiscoveredType(Type::FunctionType(Type::VoidType(), platform->GetDefaultCallingConvention(), params, false, false, 0));
			}
			function->Reanalyze();
		}

		static bool PublishMain(BinaryView* view, Function* startup, uint64_t address)
		{
			auto platform = startup->GetPlatform()->GetAssociatedPlatformByAddress(address);
			if (!view->IsOffsetExecutable(address) || address == startup->GetStart() || address == view->GetEntryPoint())
				return false;
			auto function = view->GetAnalysisFunction(platform, address);
			if (!function)
				function = view->AddFunctionForAnalysis(platform, address);
			if (!function)
				return false;
			auto symbol = view->GetSymbolByAddress(address);
			if (IsCRTUtility(symbol))
				return false;
			if (!symbol || symbol->GetRawName() != "main")
			{
				view->DefineAutoSymbol(new Symbol(FunctionSymbol, "main", address));
				if (!function->HasUserType())
				{
					size_t width = view->GetAddressSize();
					auto strings = Type::PointerType(width, Type::PointerType(width, Type::IntegerType(1, true)));
					vector<FunctionParameter> params = {{"argc", Type::IntegerType(4, true)}, {"argv", strings}, {"envp", strings}};
					function->ApplyAutoDiscoveredType(Type::FunctionType(Type::IntegerType(4, true),
						platform->GetDefaultCallingConvention(), params, false, function->CanReturn(), 0));
				}
			}
			view->StoreMetadata("__BN_main_function_address", new Metadata(address), MetadataStoreEphemeral);
			return true;
		}

	public:
		bool RecognizeLowLevelIL(BinaryView* view, Function* function, LowLevelILFunction* il) override
		{
			if (view->GetTypeName() != "ELF")
				return false;
			if (function->GetPlatform()->GetName() != "freebsd-x86")
				return RecognizeRegisterStartup(view, function, il);
			bool entry = function->GetStart() == view->GetEntryPoint();
			auto wrapperInfo = view->QueryMetadata("__BN_freebsd_start1");
			bool wrapper = wrapperInfo && wrapperInfo->IsUnsignedInteger() && wrapperInfo->GetUnsignedInteger() == function->GetStart();
			if ((!entry && !wrapper) || view->QueryMetadata("__BN_main_function_address"))
				return false;
			auto ssa = il->GetSSAForm();
			if (!ssa)
				return false;
			for (size_t i = 0; i < il->GetInstructionCount(); i++)
			{
				auto call = (*il)[i];
				if (call.operation != LLIL_CALL)
					continue;
				auto target = call.GetDestExpr<LLIL_CALL>().GetValue();
				if (!target.IsConstant())
					continue;
				auto args = Arguments(il, i);
				auto targetSymbol = view->GetSymbolByAddress(target.value);
				bool startupStop = i + 1 < il->GetInstructionCount() &&
					((*il)[i + 1].operation == LLIL_NORET || (*il)[i + 1].operation == LLIL_TRAP);
				bool mayBeWrapper = !IsCRTUtility(targetSymbol) || targetSymbol->GetRawName() == "_start1";
				if (entry && startupStop && mayBeWrapper && Matches(ssa, args, 1, {0, 1, 0}, false) &&
					Matches(ssa, args, 2, {1, 0, 4}, false))
				{
					// The assembly _start forwards cleanup, argc, argv to _start1.
					auto cleanup = args.find(0);
					uint32_t edx = function->GetArchitecture()->GetRegisterByName("edx");
					if (cleanup != args.end() && cleanup->second.GetValue().state == EntryValue && cleanup->second.GetValue().value == edx)
					{
						auto next = view->GetAnalysisFunction(function->GetPlatform(), target.value);
						if (next && next != function)
						{
							view->StoreMetadata("__BN_freebsd_start1", new Metadata((uint64_t)target.value), MetadataStoreEphemeral);
							ModelEntry(function);
							if (!next->HasUserType())
							{
								auto strings = Type::PointerType(4, Type::PointerType(4, Type::IntegerType(1, true)));
								auto fptr = Type::PointerType(4, Type::FunctionType(Type::VoidType(), function->GetPlatform()->GetDefaultCallingConvention(), {}));
								next->ApplyAutoDiscoveredType(Type::FunctionType(Type::VoidType(), function->GetPlatform()->GetDefaultCallingConvention(),
									{{"cleanup", fptr}, {"argc", Type::IntegerType(4, true)}, {"argv", strings}}, false, false, 0));
							}
							next->Reanalyze();
						}
					}
				}
				if (!Matches(ssa, args, 0, {0, 1, 0}, wrapper) || !Matches(ssa, args, 1, {1, 0, 4}, wrapper) ||
					!Matches(ssa, args, 2, {1, 4, 8}, wrapper))
					continue;
				if (entry && targetSymbol && (targetSymbol->GetRawName() == "__libc_start1" ||
					targetSymbol->GetRawName() == "__libc_start1_gcrt") && args.count(4))
				{
					// Recent FreeBSD CRT passes main as the fifth argument.
					auto main = args.at(4).GetValue();
					if (main.IsConstant() && PublishMain(view, function, main.value))
					{
						ModelEntry(function);
						return true;
					}
					continue;
				}
				// Extra outgoing arguments can belong to modern libc startup, even
				// if its symbol was stripped. Noreturn alone does not distinguish
				// that helper from main, and the fifth pointer alone does not
				// prove a callback. Do not fall through to ordinary-main guessing.
				if (args.lower_bound(3) != args.end())
					continue;
				bool terminal = false;
				auto block = il->GetBasicBlockForInstruction(i);
				for (size_t j = i + 1; block && j < block->GetEnd(); j++)
				{
					auto following = (*il)[j];
					if (following.operation == LLIL_NORET)
					{
						terminal = j == i + 1;
						break;
					}
					if (following.operation == LLIL_CALL)
					{
						auto dest = following.GetDestExpr<LLIL_CALL>().GetValue();
						auto sym = dest.IsConstant() ? view->GetSymbolByAddress(dest.value) : nullptr;
						auto status = Arguments(il, j);
						if (sym && (sym->GetRawName() == "exit" || sym->GetRawName() == "_exit") && status.count(0))
						{
							terminal = IsMainResult(ssa, status.at(0), call.GetSSAForm().instructionIndex,
								function->GetPlatform()->GetDefaultCallingConvention()->GetIntegerReturnValueRegister());
						}
						break;
					}
				}
				if (terminal && PublishMain(view, function, target.value))
				{
					if (entry)
						ModelEntry(function);
					return true;
				}
			}
			return false;
		}
	};
}

void RegisterFreeBSDCRTRecognizer(Architecture* arch)
{
	FunctionRecognizer::RegisterArchitectureFunctionRecognizer(arch, new FreeBSDCRTRecognizer());
}
