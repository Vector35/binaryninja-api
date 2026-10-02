// Copyright 2026 Vector 35 Inc.
// Licensed under the Apache License, Version 2.0.

#pragma once

#include <algorithm>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <vector>

#pragma push_macro("_STD_VECTOR")
#undef _STD_VECTOR
#ifdef BINARYNINJACORE_LIBRARY
#include "activity.h"
#include "analysis.h"
#include "callingconvention.h"
#include "function.h"
#include "lowlevelilssafunction.h"
#include "lowlevelilinstruction.h"
#include "mediumlevelilfunction.h"
#include "workflow.h"
#else
#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#endif
#pragma pop_macro("_STD_VECTOR")

#include "demangler/demangled_type_node.h"

namespace BN::CppSignatureRecovery
{
#ifdef BINARYNINJACORE_LIBRARY
	using RawSSAFunction = LowLevelILSSAFunction;
#else
	using RawSSAFunction = LowLevelILFunction;
#endif

	inline BNTypeClass TypeClass(Type* type)
	{
#ifdef BINARYNINJACORE_LIBRARY
		return type->GetTypeClass();
#else
		return type->GetClass();
#endif
	}

	inline BNVariableSourceType VariableSource(const Variable& var)
	{
#ifdef BINARYNINJACORE_LIBRARY
		return var.Type();
#else
		return var.type;
#endif
	}

	inline int64_t VariableStorage(const Variable& var)
	{
#ifdef BINARYNINJACORE_LIBRARY
		return var.Storage();
#else
		return var.storage;
#endif
	}

	inline Ref<BinaryView> View(const Ref<AnalysisContext>& context)
	{
#ifdef BINARYNINJACORE_LIBRARY
		return context->GetView();
#else
		return context->GetBinaryView();
#endif
	}

	inline DemanglerConfig Config(const Ref<AnalysisContext>& context)
	{
		bool simplifyTemplates = context->GetSetting<bool>("analysis.types.templateSimplifier");
#ifdef BINARYNINJACORE_LIBRARY
		return DemanglerConfig(*context->GetFunction()->GetPlatform(), View(context), simplifyTemplates);
#else
		return DemanglerConfig(context->GetFunction()->GetPlatform(), View(context), simplifyTemplates);
#endif
	}

	// Reuse queued demangling's reference policy when finalizing a late source
	// signature. Standalone providers use the loader's registered definitions;
	// importing their physical hints prepares those references against the view.
	inline Ref<Type> Finalize(const Ref<AnalysisContext>& context, const DemanglerConfig& config,
		DemangledTypeNode type)
	{
#ifdef BINARYNINJACORE_LIBRARY
		Demangler::PreparedResult prepared(QualifiedName(), std::make_unique<DemangledTypeNode>(std::move(type)));
		return std::move(prepared).Finalize(config, context->GetSetting<bool>("analysis.defineTypesFromMangledNames")).type;
#else
		return type.Finalize(config.GetPlatform());
#endif
	}

	// The caller has already parsed with its own demangler, including private
	// source facts. Honor the same priority order as DemangleAny without parsing
	// that successful built-in result twice. A promoted demangler can instead
	// contribute its own workflow activity and physical hints.
	inline bool IsSelectedDemangler(const _STD_STRING& name, const DemanglerConfig& config,
		const _STD_STRING& builtinName)
	{
		auto demanglers = Demangler::GetList();
		for (auto it = demanglers.rbegin(); it != demanglers.rend(); ++it)
		{
			if ((*it)->GetName() == builtinName)
				return true;
			if ((*it)->IsMangledString(name))
			{
#ifdef BINARYNINJACORE_LIBRARY
				if ((*it)->Prepare(name, config).has_value())
#else
				if ((*it)->Demangle(name, config).has_value())
#endif
					return false;
			}
		}
		return false;
	}

	// Mangling describes source types, not C++ object triviality. In particular,
	// a known aggregate size does not determine whether a value is passed indirectly.
	inline bool DirectScalar(Type* type, bool allowVoid = false)
	{
		if (!type)
			return false;
		switch (TypeClass(type))
		{
		case VoidTypeClass:
			return allowVoid;
		case BoolTypeClass:
		case IntegerTypeClass:
		case FloatTypeClass:
		case EnumerationTypeClass:
		case PointerTypeClass:
			return type->GetWidth() != 0;
		default:
			return false;
		}
	}

	// A pointer has a known physical width, but a nested callback's source
	// signature must also have a known direct ABI before it can guide call analysis.
	inline bool SafeCallbackTypes(Type* type, size_t depth = 0)
	{
		if (!type || depth > 64)
			return false;
		if (TypeClass(type) == PointerTypeClass || TypeClass(type) == ArrayTypeClass)
		{
			auto child = type->GetChildType().GetValue();
			return child && SafeCallbackTypes(child, depth + 1);
		}
		if (TypeClass(type) != FunctionTypeClass)
			return true;
		auto returnType = type->GetReturnValue().type.GetValue();
		if (!DirectScalar(returnType, true) || !SafeCallbackTypes(returnType, depth + 1))
			return false;
		for (const auto& param : type->GetParameters())
			if (!DirectScalar(param.type.GetValue()) || !SafeCallbackTypes(param.type.GetValue(), depth + 1))
				return false;
		return true;
	}

	struct Hints
	{
		Ref<Type> type;
		bool parametersComplete = false;
	};

	// An encoded scalar result can remain useful when the source parameter ABI
	// is incomplete. This proposal has no parameters or argument-byte cleanup.
	inline std::optional<Hints> RecoverEncodedReturn(const Ref<AnalysisContext>& context, Type* source)
	{
		if (!source || TypeClass(source) != FunctionTypeClass || !context->GetMediumLevelILFunction())
			return std::nullopt;
		auto function = context->GetFunction();
		auto view = View(context);
		if (!function || !view)
			return std::nullopt;
		auto convention = source->GetCallingConvention().GetValue();
		if (!convention && function->GetPlatform())
			convention = function->GetPlatform()->GetDefaultCallingConvention();
		ReturnValue returnValue = source->GetReturnValue();
		if (!convention || returnValue.type.GetConfidence() <= BN_MINIMUM_CONFIDENCE
			|| !DirectScalar(returnValue.type.GetValue(), true) || !SafeCallbackTypes(returnValue.type.GetValue()))
			return std::nullopt;
		auto layout = convention->GetCallLayout(view, returnValue, {});
		ValueLocation location;
		if (layout.returnValue.has_value())
			location = *layout.returnValue;
		if (location.indirect || location.returnedPointer.has_value())
			return std::nullopt;
		bool isVoid = TypeClass(returnValue.type.GetValue()) == VoidTypeClass;
		if (isVoid != location.components.empty())
			return std::nullopt;
		auto arch = function->GetArchitecture();
		uint64_t width = returnValue.type->GetWidth();
		for (const auto& component : location.components)
		{
			auto storage = VariableStorage(component.variable);
			if (VariableSource(component.variable) != RegisterVariableSourceType
				|| LLIL_REG_IS_TEMP(storage) || component.offset < 0 || (uint64_t)component.offset >= width)
				return std::nullopt;
			uint64_t remainingWidth = width - (uint64_t)component.offset;
			uint64_t pieceWidth = component.size.value_or(remainingWidth);
			if (pieceWidth == 0 || pieceWidth > remainingWidth
				|| pieceWidth > arch->GetRegisterInfo((uint32_t)storage).size)
				return std::nullopt;
		}
		returnValue.defaultLocation = false;
		returnValue.location = Confidence<ValueLocation>(location, BN_HEURISTIC_CONFIDENCE);
		Ref<Type> result = Type::FunctionType(returnValue,
			Confidence<Ref<CallingConvention>>(convention, 0), {});
		return Hints{result, false};
	}

	inline std::optional<Hints> Recover(const Ref<AnalysisContext>& context, Type* source, bool optionalThis,
		bool receiverOnly = false, bool knownNoIndirectResult = false)
	{
		if (!source || TypeClass(source) != FunctionTypeClass || !context->GetMediumLevelILFunction())
			return std::nullopt;
		auto function = context->GetFunction();
		auto lowLevelIL = context->GetLowLevelILFunction();
		if (!function || !lowLevelIL || !lowLevelIL->GetSSAForm())
			return std::nullopt;
		Ref<RawSSAFunction> il = lowLevelIL->GetSSAForm();
		auto view = View(context);
		auto convention = source->GetCallingConvention().GetValue();
		if (!convention && function->GetPlatform())
			convention = function->GetPlatform()->GetDefaultCallingConvention();
		if (!view || !convention)
			return std::nullopt;

		auto params = source->GetParameters();
		if (receiverOnly)
		{
			if (params.empty() || params.front().name != "this" || !params.front().type.GetValue()
				|| TypeClass(params.front().type.GetValue()) != PointerTypeClass)
				return std::nullopt;
			params.resize(1);
		}
		for (const auto& param : params)
			if (!DirectScalar(param.type.GetValue()) || !SafeCallbackTypes(param.type.GetValue()))
				return std::nullopt;
		ReturnValue returnValue = source->GetReturnValue();
		if (!DirectScalar(returnValue.type.GetValue(), true) || !SafeCallbackTypes(returnValue.type.GetValue()))
			return std::nullopt;
		bool unencodedReturn = returnValue.type.GetConfidence() <= BN_MINIMUM_CONFIDENCE;
		if (receiverOnly && ((unencodedReturn && !knownNoIndirectResult)
			|| TypeClass(returnValue.type.GetValue()) != VoidTypeClass))
			return std::nullopt;

		std::set<uint32_t> inputRegisters;
		for (auto reg : convention->GetIntegerArgumentRegisters())
			inputRegisters.insert(reg);
		for (auto reg : convention->GetFloatArgumentRegisters())
			inputRegisters.insert(reg);
		auto indirectResult = convention->GetIndirectReturnValueLocation();
		if (VariableSource(indirectResult) == RegisterVariableSourceType)
			inputRegisters.insert((uint32_t)VariableStorage(indirectResult));

		std::map<uint32_t, size_t> observedWidths;
		auto collect = [&](auto&& self, const LowLevelILInstruction& expr, size_t widthLimit) -> void {
			if (expr.operation == LLIL_REG_SSA || expr.operation == LLIL_REG_SSA_PARTIAL)
			{
				auto reg = expr.GetSourceSSARegister();
				if (reg.version == 0 && inputRegisters.count(reg.reg))
					observedWidths[reg.reg] = std::max(observedWidths[reg.reg], std::min(expr.size, widthLimit));
				return;
			}
			if (expr.operation == LLIL_LOW_PART)
			{
				self(self, expr.GetSourceExpr<LLIL_LOW_PART>(), std::min(expr.size, widthLimit));
				return;
			}
			for (const auto& operand : expr.GetOperands())
			{
				if (operand.GetType() == ExprLowLevelOperand)
					self(self, operand.GetExpr(), widthLimit);
				else if (operand.GetType() == ExprListLowLevelOperand)
					for (const auto& child : operand.GetExprList())
						self(self, child, widthLimit);
			}
		};

		// Raw versioned LLIL values do not depend on a mapped, previously analyzed
		// MLIL pass. The ordinary instruction-value APIs can consult that old pass.
		auto returnReg = convention->GetIntegerReturnValueRegister();
		bool possibleIndirectResult = false;
		for (size_t i = 0; i < il->GetInstructionCount(); ++i)
		{
			auto instr = il->GetInstruction(i);
			if (unencodedReturn && !knownNoIndirectResult && VariableSource(indirectResult) == RegisterVariableSourceType)
			{
				if (instr.operation == LLIL_STORE_SSA)
				{
					instr.GetDestExpr<LLIL_STORE_SSA>().VisitExprs([&](const LowLevelILInstruction& expr) {
						if (expr.operation == LLIL_REG_SSA || expr.operation == LLIL_REG_SSA_PARTIAL)
						{
							auto value = il->GetSSARegisterValue(expr.GetSourceSSARegister());
							if (value.state == UndeterminedValue || (value.state == EntryValue
								&& value.value == VariableStorage(indirectResult)))
								possibleIndirectResult = true;
						}
						return true;
					});
				}
				if (returnReg != BN_INVALID_REGISTER && (instr.operation == LLIL_SET_REG_SSA
					|| instr.operation == LLIL_SET_REG_SSA_PARTIAL || instr.operation == LLIL_REG_PHI))
				{
					auto dest = instr.GetDestSSARegister();
					if (dest.reg == returnReg)
					{
						auto value = il->GetSSARegisterValue(dest);
						possibleIndirectResult |= value.state == EntryValue && value.value == VariableStorage(indirectResult);
					}
				}
			}
			switch (instr.operation)
			{
			case LLIL_CALL_SSA:
			case LLIL_CALL_STACK_ADJUST:
			case LLIL_TAILCALL_SSA:
				// A forwarded unencoded result may use the incoming hidden buffer.
				if (unencodedReturn && !knownNoIndirectResult)
					return std::nullopt;
				continue;
			case LLIL_SYSCALL_SSA:
			case LLIL_REG_PHI:
			case LLIL_ASSERT_SSA:
				continue;
			case LLIL_UNIMPL:
			case LLIL_UNIMPL_MEM:
				return std::nullopt;
			default:
				collect(collect, instr, SIZE_MAX);
				break;
			}
		}
		// A required receiver does not determine its slot when a hidden result
		// pointer precedes it. Opaque output-buffer stores are ambiguous as well.
		if (possibleIndirectResult)
			return std::nullopt;

		struct Candidate
		{
			CallLayout layout;
			bool supported = true;
			bool contradicted = false;
		};
		auto evaluate = [&](const auto& candidateParams) {
			Candidate candidate;
			candidate.layout = convention->GetCallLayout(view, returnValue, candidateParams);
			if (candidate.layout.parameters.size() != candidateParams.size())
			{
				candidate.supported = false;
				return candidate;
			}
			std::set<uint32_t> explained;
			for (size_t i = 0; i < candidateParams.size(); ++i)
			{
				const auto& location = candidate.layout.parameters[i];
				if (location.indirect || location.components.size() != 1
					|| VariableSource(location.components.front().variable) != RegisterVariableSourceType)
				{
					candidate.supported = false;
					continue;
				}
				const auto& component = location.components.front();
				auto reg = (uint32_t)VariableStorage(component.variable);
				explained.insert(reg);
				auto observed = observedWidths.find(reg);
				// Narrow pointer uses and integer address casts do not disprove this.
				if (observed != observedWidths.end()
					&& observed->second > component.size.value_or(candidateParams[i].type->GetWidth()))
					candidate.contradicted = true;
			}
			for (const auto& [reg, width] : observedWidths)
				if (!receiverOnly && !explained.count(reg))
					candidate.contradicted = true;
			return candidate;
		};

		auto withThis = evaluate(params);
		if (!withThis.supported || withThis.contradicted)
			return std::nullopt;
		bool complete = true;
		std::vector<size_t> retained;
		if (receiverOnly)
		{
			// Receiver existence and its first slot are independently established
			// for the base variant. Retain only an observed receiver, leaving VTT
			// and every explicit argument to physical parameter recovery.
			auto reg = (uint32_t)VariableStorage(withThis.layout.parameters[0].components.front().variable);
			if (!observedWidths.count(reg))
				return std::nullopt;
			retained.push_back(0);
			complete = false;
		}
		else if (optionalThis && !params.empty() && params.front().name == "this")
		{
			auto withoutParams = params;
			withoutParams.erase(withoutParams.begin());
			auto withoutThis = evaluate(withoutParams);
			if (!withoutThis.supported)
				return std::nullopt;
			if (!withoutThis.contradicted)
			{
				// Only observed slots invariant under both source interpretations are
				// safe hints. Independent integer and floating-point banks often permit this.
				complete = false;
				for (size_t i = 1; i < params.size(); ++i)
				{
					const auto& location = withThis.layout.parameters[i];
					if (location == withoutThis.layout.parameters[i - 1]
						&& observedWidths.count((uint32_t)VariableStorage(location.components.front().variable)))
						retained.push_back(i);
				}
				if (retained.empty())
					return std::nullopt;
			}
		}
		if (complete)
			for (size_t i = 0; i < params.size(); ++i)
				retained.push_back(i);

		_STD_VECTOR<FunctionParameter> recoveredParams;
		for (auto index : retained)
		{
			auto param = params[index];
			param.locationSource = CustomLocationSource;
			param.location = withThis.layout.parameters[index];
			recoveredParams.push_back(std::move(param));
		}
		if (unencodedReturn)
			returnValue = ReturnValue(Confidence<Ref<Type>>(Type::VoidType(), 0));
		Ref<Type> result = Type::FunctionType(returnValue,
			Confidence<Ref<CallingConvention>>(convention, BN_HEURISTIC_CONFIDENCE), recoveredParams,
			source->HasVariableArguments(), source->CanReturn(), source->GetStackAdjustment(), {}, NoNameType, source->IsPure());
		return Hints{result, complete};
	}

	inline bool Register(const _STD_STRING& name, const _STD_STRING& title,
		const std::function<void(Ref<AnalysisContext>)>& action)
	{
		_STD_STRING configuration = "{\"name\":\"" + name + "\",\"title\":\"" + title
			+ "\",\"description\":\"Recover physical parameter types from source signatures and independent IL evidence\","
			"\"eligibility\":{\"auto\":{},\"predicates\":[{\"type\":\"setting\","
			"\"identifier\":\"analysis.applyTypesFromMangledNames\",\"value\":true}]}}";
#ifdef BINARYNINJACORE_LIBRARY
		Ref<Activity> activity = new Activity(configuration, new StaticFunctionDelegate(action));
#else
		Ref<Activity> activity = new Activity(configuration, action);
#endif
		return Workflow::RegisterActivityExtension("core.function.analyzeMediumLevelIL", activity);
	}
}
