#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <string>
#include <tuple>
#include <unordered_map>

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"


using namespace BinaryNinja;
using namespace std;

#if defined(_MSC_VER)
#define snprintf _snprintf
#endif


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

	// TODO: Replace with analysis cache opaque datastore.
	std::mutex g_mutex;
	unordered_map<void*, unordered_map<uint64_t, tuple<string, uint64_t>>> g_classData;

	// TODO
	// * __objc_const missing xrefs to implementations
	void ObjectiveCAnalysis(Ref<AnalysisContext> analysisContext)
	{
		Ref<Function> function = analysisContext->GetFunction();
		Ref<BinaryView> data = function->GetView();

		// TODO 1) Move this to run-once workflow activity 2) stash data in analysis cache opaque datastore.
		std::unique_lock<std::mutex> lock(g_mutex);
		auto gItr = g_classData.find(data->GetObject());
		if (gItr == g_classData.end())
		{
			auto constSection = data->GetSectionByName("__objc_const");
			if (!constSection)
				return;

			BinaryReader reader(data);
			reader.SetEndianness(data->GetDefaultEndianness()); // TODO fix GetDefaultEndianness for non-elf formats
			reader.Seek(constSection->GetStart());

			reader.Read32();
			reader.Read32();
			reader.Read32();
			reader.Read32();
			reader.Read64();
			uint64_t namePtr = reader.Read64();
			reader.Read64();
			reader.Read64();
			reader.Read64();
			reader.Read64();
			reader.Read64();
			uint32_t methodListFlags = reader.Read32();
			uint32_t methodListCount = reader.Read32();
			for (uint32_t i = 0; i < methodListCount; i++) // section end/symbol validation
			{
				uint64_t selector = reader.Read64();
				uint64_t typePtr = reader.Read64();
				uint64_t impPtr = reader.Read64();
				//string methodName = reader.ReadCString(selector);
				string typeEncoding = "";//reader.ReadCString(typePtr);
				g_classData[data->GetObject()].insert_or_assign(selector, std::forward_as_tuple(typeEncoding, impPtr));
			}

			// TODO cfstring
			// reader.Seek(namePtr);
			// string className = reader.ReadCString();

			// auto cfStringSection = data->GetSectionByName("__cfstring");
			// if (!cfStringSection)
			// 	return;
		}

		auto& classData = gItr->second;
		lock.unlock();

		bool updated = false;
		uint8_t opcode[BN_MAX_INSTRUCTION_LENGTH];
		InstructionInfo iInfo;

		// if (m_owner->IsAborted())
		// 	return;

		// TODO fix this....
		auto sym = data->GetSymbolByRawName("_objc_msgSend");
		if (!sym)
			return;
		uint64_t msgSendAddr = sym->GetAddress();

		Ref<LowLevelILFunction> llilFunc = analysisContext->GetLowLevelILFunction();
		auto ssa = llilFunc->GetSSAForm();
		if (!ssa)
			return;
		for (auto& i : ssa->GetBasicBlocks())
		{
			Ref<Architecture> arch = i->GetArchitecture();
			for (size_t instrIndex = i->GetStart(); instrIndex < i->GetEnd(); instrIndex++)
			{
				LowLevelILInstruction instr = ssa->GetInstruction(instrIndex);

				// TODO process subexpressions
				if (instr.operation != LLIL_CALL_SSA)
					continue;

				LowLevelILInstruction destExpr = instr.GetDestExpr<LLIL_CALL_SSA>();
				if (msgSendAddr == (uint64_t)destExpr.GetValue().value)
				{
					auto params = instr.GetParameterExprs<LLIL_CALL_SSA>();
					if ((params.size() >= 2) && (params[0].operation == LLIL_REG_SSA) && (params[1].operation == LLIL_REG_SSA))
					{
						auto selfSSAReg = params[0].GetSourceSSARegister<LLIL_REG_SSA>();
						auto selSSAReg = params[1].GetSourceSSARegister<LLIL_REG_SSA>();
						if (auto itr = classData.find(ssa->GetSSARegisterValue(selSSAReg).value); itr != classData.end())
						{
							size_t llilIndex = ssa->GetNonSSAInstructionIndex(instrIndex);
							LowLevelILInstruction llilInstr = llilFunc->GetInstruction(llilIndex);
							auto destExpr = llilInstr.GetDestExpr<LLIL_CALL>();
							const auto& [typeEncoding, impPtr] = itr->second;
							destExpr.Replace(llilFunc->ConstPointer(destExpr.size, impPtr, destExpr));
							llilInstr.Replace(llilFunc->Call(destExpr.exprIndex, llilInstr));
							analysisContext->Inform("directRefs", "insert", impPtr, i->GetArchitecture(), instr.address);
							updated = true;
						}
					}
					// else
					// 	LogError("Unhandled _objc_msgSend: 0x%" PRIx64, instr.address);
				}
			}
		}

		if (!updated)
			return;

		// Updates found, regenerate SSA form
		llilFunc->GenerateSSAForm();
	}


	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		Ref<Workflow> objectiveCWorkflow = Workflow::Instance()->Clone("ObjectiveCWorkflow");
		objectiveCWorkflow->RegisterActivity(new Activity("extension.objectiveC", &ObjectiveCAnalysis));
		objectiveCWorkflow->Insert("core.function.translateTailCalls", "extension.objectiveC");
		Workflow::RegisterWorkflow(objectiveCWorkflow,
			R"#({
			"title" : "Objective C Meta-Analysis (Example)",
			"description" : "This analysis stands in as an example to demonstrate Binary Ninja's extensible analysis APIs. ***Note** this feature is under active development and subject to change without notice.",
			"capabilities" : []
			})#");

		return true;
	}
}
