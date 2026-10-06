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
		bool receiverUsed = false;
	};

	struct ReceiverInfo
	{
		DemangledReceiverKind kind = DemangledReceiverKind::None;
		Ref<Type> type;
		DemangledTypeNode::NodeRef receiverNode;
		std::optional<size_t> explicitObjectParameterIndex;
	};

	inline ReceiverInfo Receiver(const Ref<AnalysisContext>& context, const DemanglerConfig& config,
		const DemangledTypeNode& source)
	{
		ReceiverInfo result;
		result.kind = source.GetReceiverKind();
		result.receiverNode = source.GetReceiverType();
		result.explicitObjectParameterIndex = source.GetExplicitObjectParameterIndex();
		// Resolve existing identities (including renamed/user types) without
		// registering an uncertain owner as a class before ABI validation.
		if (result.receiverNode)
		{
			auto view = View(context);
			if (view)
			{
				auto resolve = [&](const DemangledTypeReferenceRequest& request) -> Ref<NamedTypeReference> {
#ifdef BINARYNINJACORE_LIBRARY
					auto lookup = request;
					lookup.registration = DemangledTypeReferenceRegistration::DoNotRegister;
					return view->GetAnalysis()->ResolveDemangledTypeReference(lookup);
#else
					auto id = view->GetTypeId(request.name);
					if (!id.empty() && view->GetTypeById(id))
						return new NamedTypeReference(request.typeClass, id, request.name);
					id = Type::GenerateAutoDemangledTypeId(request.name);
					if (view->GetTypeById(id))
						return new NamedTypeReference(request.typeClass, id, view->GetTypeNameById(id));
					return NamedTypeReference::GenerateAutoDemangledTypeReference(request.typeClass, request.name);
#endif
				};
				result.type = result.receiverNode->Finalize(config.GetPlatform(), resolve);
			}
			else
				result.type = result.receiverNode->Finalize(config.GetPlatform());
		}
		return result;
	}

	inline bool HasImplicitReceiver(const ReceiverInfo& receiver)
	{
		return receiver.kind == DemangledReceiverKind::Candidate || receiver.kind == DemangledReceiverKind::Required;
	}

	inline _STD_VECTOR<FunctionParameter> ParametersWithReceiver(Type* source, const ReceiverInfo& receiver)
	{
		auto params = source->GetParameters();
		if (HasImplicitReceiver(receiver))
			params.insert(params.begin(), FunctionParameter("this", Confidence<Ref<Type>>(receiver.type, BN_FULL_CONFIDENCE),
				DefaultLocationSource, ValueLocation()));
		return params;
	}

	inline void RegisterUsedReceiver(const Ref<AnalysisContext>& context, const DemanglerConfig& config,
		const ReceiverInfo& receiver, const Hints& hints)
	{
		if (hints.receiverUsed && receiver.receiverNode)
			Finalize(context, config, *receiver.receiverNode);
	}

	inline bool DirectResultLocationSupported(Type* type, const ValueLocation& location, Architecture* arch)
	{
		if (!type || !arch || location.indirect || location.returnedPointer.has_value())
			return false;
		const bool isVoid = TypeClass(type) == VoidTypeClass;
		if (isVoid != location.components.empty())
			return false;
		const uint64_t width = type->GetWidth();
		for (const auto& component : location.components)
		{
			auto storage = VariableStorage(component.variable);
			if (VariableSource(component.variable) != RegisterVariableSourceType
				|| LLIL_REG_IS_TEMP(storage) || component.offset < 0 || (uint64_t)component.offset >= width)
				return false;
			const uint64_t remainingWidth = width - (uint64_t)component.offset;
			const uint64_t pieceWidth = component.size.value_or(remainingWidth);
			if (pieceWidth == 0 || pieceWidth > remainingWidth
				|| pieceWidth > arch->GetRegisterInfo((uint32_t)storage).size)
				return false;
		}
		return true;
	}

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
		if (!DirectResultLocationSupported(returnValue.type.GetValue(), location, function->GetArchitecture()))
			return std::nullopt;
		returnValue.defaultLocation = false;
		// The encoded scalar result and its calling convention determine this
		// physical slot independently of the incomplete parameter list. A lower
		// confidence would let an incidental clobbered register replace the result.
		returnValue.location = Confidence<ValueLocation>(location, BN_FULL_CONFIDENCE);
		Ref<Type> result = Type::FunctionType(returnValue,
			Confidence<Ref<CallingConvention>>(convention, 0), {});
		return Hints{result, false};
	}

	inline std::optional<Hints> Recover(const Ref<AnalysisContext>& context, Type* source, const ReceiverInfo& receiver,
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

		const bool implicitReceiver = HasImplicitReceiver(receiver);
		if (implicitReceiver && (!receiver.type || TypeClass(receiver.type) != PointerTypeClass))
			return std::nullopt;
		auto params = ParametersWithReceiver(source, receiver);
		if (receiverOnly)
		{
			if (!implicitReceiver || params.empty() || !params.front().type.GetValue()
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
		auto architecture = function->GetArchitecture();
		bool dedicatedIndirectResult = false;
		if (VariableSource(indirectResult) == RegisterVariableSourceType)
		{
			auto storage = VariableStorage(indirectResult);
			if (storage >= 0 && (uint64_t)storage <= UINT32_MAX && !LLIL_REG_IS_TEMP(storage))
			{
				auto info = architecture->GetRegisterInfo((uint32_t)storage);
				if (info.size >= architecture->GetAddressSize() && info.fullWidthRegister != BN_INVALID_REGISTER)
				{
					dedicatedIndirectResult = true;
					for (auto reg : inputRegisters)
						if (architecture->GetRegisterInfo(reg).fullWidthRegister == info.fullWidthRegister)
							dedicatedIndirectResult = false;
				}
			}
		}
		// A dedicated result register does not shift the source argument slots.
		// Keep those scalar bindings useful without claiming a complete physical
		// list: machine recovery must still retain a possible hidden result input.
		bool partialResultABI = false;
		if (VariableSource(indirectResult) == RegisterVariableSourceType)
			inputRegisters.insert((uint32_t)VariableStorage(indirectResult));
		// Some ABIs, including AAPCS32, need not return the hidden result
		// pointer. An empty nontrivial result can leave neither stores nor a
		// returned pointer in the body. Its shared result slot still shifts the
		// declared inputs, so absence of those observations cannot validate them.
		const bool unobservedResultMayShiftParameters = unencodedReturn && !knownNoIndirectResult
			&& !dedicatedIndirectResult && !convention->GetReturnedIndirectReturnValuePointer().has_value();

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
				{
					if (!dedicatedIndirectResult)
						return std::nullopt;
					partialResultABI = true;
				}
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
		{
			if (!dedicatedIndirectResult)
				return std::nullopt;
			partialResultABI = true;
		}

		struct Candidate
		{
			CallLayout layout;
			bool supported = true;
			bool contradicted = false;
			bool hasUnexplainedInputs = false;
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
				if (!receiverOnly && !explained.count(reg)
					&& !(partialResultABI && architecture->GetRegisterInfo(reg).fullWidthRegister
						== architecture->GetRegisterInfo((uint32_t)VariableStorage(indirectResult)).fullWidthRegister))
				{
					candidate.contradicted = true;
					candidate.hasUnexplainedInputs = true;
				}
			return candidate;
		};

		auto withReceiver = evaluate(params);
		if (!withReceiver.supported || withReceiver.contradicted)
			return std::nullopt;
		bool complete = true;
		std::vector<size_t> retained;
		if (receiverOnly)
		{
			// Receiver existence and its first slot are independently established
			// for the base variant. Retain only an observed receiver, leaving VTT
			// and every explicit argument to physical parameter recovery.
			auto reg = (uint32_t)VariableStorage(withReceiver.layout.parameters[0].components.front().variable);
			if (!observedWidths.count(reg))
				return std::nullopt;
			retained.push_back(0);
			complete = false;
		}
		else if (receiver.kind == DemangledReceiverKind::Candidate)
		{
			auto withoutParams = params;
			withoutParams.erase(withoutParams.begin());
			auto withoutReceiver = evaluate(withoutParams);
			if (!withoutReceiver.supported)
				return std::nullopt;
			// Argument forwarding can copy ABI extension bits of a narrower
			// scalar. A wider read alone cannot establish an optional receiver
			// in the preceding register slot, even when the result ABI is direct.
			if (!withoutReceiver.contradicted || !withoutReceiver.hasUnexplainedInputs)
			{
				// Only observed slots invariant under both source interpretations are
				// safe hints. Independent integer and floating-point banks often permit this.
				complete = false;
				for (size_t i = 1; i < params.size(); ++i)
				{
					const auto& location = withReceiver.layout.parameters[i];
					if (location == withoutReceiver.layout.parameters[i - 1]
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
		if (unobservedResultMayShiftParameters)
		{
			// Compare physical bindings rather than guessing the unencoded
			// result's source type or triviality. Independent floating banks can
			// remain useful; shifted integer/stack bindings must be deferred.
			ReturnValue indirectReturn(Type::PointerType(architecture->GetAddressSize(), Type::VoidType()), false,
				Confidence<ValueLocation>(ValueLocation({indirectResult}, true), BN_FULL_CONFIDENCE));
			auto indirectLayout = convention->GetCallLayout(view, indirectReturn, params);
			if (indirectLayout.parameters.size() != params.size())
				return std::nullopt;
			std::erase_if(retained, [&](size_t index) {
				const auto& location = withReceiver.layout.parameters[index];
				return location != indirectLayout.parameters[index]
					|| !observedWidths.count((uint32_t)VariableStorage(location.components.front().variable));
			});
			complete = false;
			if (retained.empty())
				return std::nullopt;
		}
		if (partialResultABI)
		{
			complete = false;
			if (retained.empty())
				return std::nullopt;
		}

		_STD_VECTOR<FunctionParameter> recoveredParams;
		for (auto index : retained)
		{
			auto param = params[index];
			param.locationSource = CustomLocationSource;
			param.location = withReceiver.layout.parameters[index];
			recoveredParams.push_back(std::move(param));
		}
		if (unencodedReturn)
			returnValue = ReturnValue(Confidence<Ref<Type>>(Type::VoidType(), 0));
		else
		{
			ValueLocation location = withReceiver.layout.returnValue.value_or(ValueLocation());
			if (!DirectResultLocationSupported(returnValue.type.GetValue(), location, function->GetArchitecture()))
				return std::nullopt;
			returnValue.defaultLocation = false;
			returnValue.location = Confidence<ValueLocation>(location, BN_FULL_CONFIDENCE);
		}
		Ref<Type> result = Type::FunctionType(returnValue,
			Confidence<Ref<CallingConvention>>(convention, BN_HEURISTIC_CONFIDENCE), recoveredParams,
			source->HasVariableArguments(), source->CanReturn(), source->GetStackAdjustment(), {}, NoNameType, source->IsPure());
		bool receiverUsed = implicitReceiver && std::find(retained.begin(), retained.end(), 0) != retained.end();
		return Hints{result, complete, receiverUsed};
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
