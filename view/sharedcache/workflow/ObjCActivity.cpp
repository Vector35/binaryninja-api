#include "ObjCActivity.h"
#include "lowlevelilinstruction.h"

// TODO: Consolidate this with the Obj-C workflow at some point https://github.com/Vector35/workflow_objc

using namespace BinaryNinja;

void ObjCActivity::Register(Workflow &workflow)
{
    workflow.RegisterActivity(new Activity("core.analysis.objc.adjustCallType", &AdjustCallType));
	workflow.Insert("core.function.analyzeTailCalls", "core.analysis.objc.adjustCallType");
}

std::vector<std::string> splitSelector(const std::string& selector) {
	std::vector<std::string> components;
	std::istringstream stream(selector);
	std::string component;

	while (std::getline(stream, component, ':')) {
		if (!component.empty()) {
			components.push_back(component);
		}
	}

	return components;
}

std::vector<std::string> generateArgumentNames(const std::vector<std::string>& components) {
	std::vector<std::string> argumentNames;

	for (const std::string& component : components) {
		size_t startPos = component.find_last_of(' ');
		std::string argumentName = (startPos == std::string::npos) ? component : component.substr(startPos + 1);
		argumentNames.push_back(argumentName);
	}

	return argumentNames;
}

void ObjCActivity::AdjustCallType(Ref<AnalysisContext> ctx)
{
    const auto func = ctx->GetFunction();
	const auto arch = func->GetArchitecture();
	const auto bv = func->GetView();

	const auto llil = ctx->GetLowLevelILFunction();
	if (!llil) {
		return;
	}
	const auto ssa = llil->GetSSAForm();
	if (!ssa) {
		return;
	}

	const auto rewriteIfEligible = [bv, ssa](size_t insnIndex) {
		auto insn = ssa->GetInstruction(insnIndex);
		if (insn.operation != LLIL_CALL_SSA)
			return;

		enum class MessageSendType {
			Normal,
			Super,
		};

		MessageSendType messageSendType = MessageSendType::Normal;
		// Filter out calls that aren't to `objc_msgSend`, `objc_msgSendSuper`, or `objc_msgSendSuper2`.
		auto callExpr = insn.GetDestExpr<LLIL_CALL_SSA>();
		if (auto symbol = bv->GetSymbolByAddress(callExpr.GetValue().value))
		{
			std::string_view symbolName = symbol->GetRawNameRef();
			if (symbolName == "_objc_msgSend")
				messageSendType = MessageSendType::Normal;
			else if (symbolName == "_objc_msgSendSuper2" || symbolName == "_objc_msgSendSuper")
				messageSendType = MessageSendType::Super;
			else
			 	return;
		}

		const auto params = insn.GetParameterExprs<LLIL_CALL_SSA>();
		// The second parameter passed to the objc_msgSend call is the address of
		// either the selector reference or the method's name, which in both cases
		// is dereferenced to retrieve a selector.
		if (params.size() < 2)
			return;
		uint64_t rawSelector = 0;
		if (params[1].operation == LLIL_REG_SSA)
		{
			const auto selectorRegister = params[1].GetSourceSSARegister<LLIL_REG_SSA>();
			rawSelector = ssa->GetSSARegisterValue(selectorRegister).value;
		}
		else if (params[0].operation == LLIL_SEPARATE_PARAM_LIST_SSA)
		{
			if (params[0].GetParameterExprs<LLIL_SEPARATE_PARAM_LIST_SSA>().size() == 0)
				return;
			const auto selectorRegister = params[0].GetParameterExprs<LLIL_SEPARATE_PARAM_LIST_SSA>()[1].GetSourceSSARegister<LLIL_REG_SSA>();
			rawSelector = ssa->GetSSARegisterValue(selectorRegister).value;
		}
		if (!rawSelector || !bv->IsValidOffset(rawSelector))
			return;

		// -- Do callsite override
		auto reader = BinaryReader(bv);
		reader.Seek(rawSelector);
		auto selector = reader.ReadCString(500);
		auto additionalArgumentCount = std::count(selector.begin(), selector.end(), ':');

		auto retType = bv->GetTypeByName({ "id" });
		if (!retType)
			retType = Type::PointerType(ssa->GetArchitecture(), Type::VoidType());

		std::vector<FunctionParameter> callTypeParams;
		auto cc = bv->GetDefaultPlatform()->GetDefaultCallingConvention();

		if (messageSendType == MessageSendType::Normal)
			callTypeParams.emplace_back("self", retType, true, Variable());
		else
		{
			auto superType = bv->GetTypeByName({ "objc_super" });
			if (!superType)
				superType = Type::PointerType(ssa->GetArchitecture(), Type::VoidType());
			callTypeParams.emplace_back("super", Type::PointerType(ssa->GetArchitecture(), superType), true, Variable());
		}

		auto selType = bv->GetTypeByName({ "SEL" });
		if (!selType)
			selType = Type::PointerType(ssa->GetArchitecture(), Type::IntegerType(1, true));
		callTypeParams.emplace_back("sel", selType, true, Variable());

		std::vector<std::string> selectorComponents = splitSelector(selector);
		std::vector<std::string> argumentNames = generateArgumentNames(selectorComponents);

		for (size_t i = 0; i < additionalArgumentCount; i++)
		{
			auto argType = Type::IntegerType(bv->GetAddressSize(), true);
			if (argumentNames.size() > i && !argumentNames[i].empty())
				callTypeParams.emplace_back(argumentNames[i], argType, true, Variable());
			else
				callTypeParams.emplace_back("arg" + std::to_string(i), argType, true, Variable());
		}

		auto funcType = Type::FunctionType(retType, cc, callTypeParams);
		ssa->GetFunction()->SetAutoCallTypeAdjustment(ssa->GetFunction()->GetArchitecture(), insn.address, {funcType, BN_DEFAULT_CONFIDENCE});
		// --
	};

	for (const auto& block : ssa->GetBasicBlocks())
		for (size_t i = block->GetStart(), end = block->GetEnd(); i < end; ++i)
			rewriteIfEligible(i);
}

