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
			size_t call, uint32_t resultRegister, size_t depth = 0)
		{
			if (depth > 16 || value.operation != LLIL_REG_SSA || value.size != 4)
				return false;
			auto reg = value.GetSourceSSARegister<LLIL_REG_SSA>();
			size_t definition = ssa->GetSSARegisterDefinition(reg);
			if (definition == call)
				return reg.reg == resultRegister;
			if (definition == BN_INVALID_EXPR)
				return false;
			auto copy = (*ssa)[definition];
			return copy.operation == LLIL_SET_REG_SSA &&
				IsMainResult(ssa, copy.GetSourceExpr<LLIL_SET_REG_SSA>(), call, resultRegister, depth + 1);
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
			if (!view->IsOffsetExecutable(address) || address == startup->GetStart())
				return false;
			auto function = view->GetAnalysisFunction(startup->GetPlatform(), address);
			if (!function)
				function = view->AddFunctionForAnalysis(startup->GetPlatform(), address);
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
					auto strings = Type::PointerType(4, Type::PointerType(4, Type::IntegerType(1, true)));
					vector<FunctionParameter> params = {{"argc", Type::IntegerType(4, true)}, {"argv", strings}, {"envp", strings}};
					function->ApplyAutoDiscoveredType(Type::FunctionType(Type::IntegerType(4, true),
						startup->GetPlatform()->GetDefaultCallingConvention(), params, false, function->CanReturn(), 0));
				}
			}
			view->StoreMetadata("__BN_main_function_address", new Metadata(address), MetadataStoreEphemeral);
			return true;
		}

	public:
		bool RecognizeLowLevelIL(BinaryView* view, Function* function, LowLevelILFunction* il) override
		{
			if (view->GetTypeName() != "ELF" || function->GetPlatform()->GetName() != "freebsd-x86")
				return false;
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
