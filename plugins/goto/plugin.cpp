#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"

using namespace BinaryNinja;

std::unordered_map<uint64_t, uint64_t> GetGotoMap(const Ref<BinaryView>& view)
{
	std::unordered_map<uint64_t, uint64_t> result;
	auto metadata = view->QueryMetadata("gotos");
	if (!metadata || !metadata->IsKeyValueStore())
		return result;
	for (auto& kv: metadata->GetKeyValueStore())
		result[std::stoul(kv.first)] = kv.second->GetUnsignedInteger();
	return result;
}

void AddGoto(const Ref<BinaryView>& view, uint64_t address, uint64_t target)
{
	auto metadata = view->QueryMetadata("gotos");
	if (!metadata)
		metadata = new Metadata(KeyValueDataType);
	std::string key = std::to_string(address);
	metadata->SetValueForKey(key, new Metadata(target));
	view->StoreMetadata("gotos", metadata);
}

void ForceGoto(const Ref<AnalysisContext>& analysisContext)
{
	auto view = analysisContext->GetBinaryView();
	auto gotos = GetGotoMap(view);
	if (gotos.empty())
		return;

	auto llil = analysisContext->GetFunction()->GetLiftedIL();
	if (!llil)
		return;

	bool updated = false;
	for (auto& i : llil->GetBasicBlocks())
	{
		Ref<Architecture> arch = i->GetArchitecture();
		for (size_t instrIndex = i->GetStart(); instrIndex < i->GetEnd(); instrIndex++)
		{
			LowLevelILInstruction instr = llil->GetInstruction(instrIndex);
			// Skip already forced gotos.
			if (instr.operation == LLIL_GOTO)
				continue;

			auto forcedGoto = gotos.find(instr.address);
			if (forcedGoto == gotos.end())
				continue;
			auto forcedGotoTarget = forcedGoto->second;

			auto targetLabel = llil->GetLabelForAddress(arch, forcedGotoTarget);
			if (!targetLabel)
			{
				llil->AddLabelForAddress(arch, forcedGotoTarget);
				targetLabel = llil->GetLabelForAddress(arch, forcedGotoTarget);
			}

			instr.Replace(llil->Goto(*targetLabel));
			LogInfo("Forcing goto at 0x%llx to 0x%llx", instr.address, forcedGotoTarget);
			updated = true;
		}
	}

	if (updated)
		llil->GenerateSSAForm();
}


extern "C" {
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		Ref<Workflow> metaWorkflow = Workflow::Instance("core.function.metaAnalysis")->Clone();

		metaWorkflow->RegisterActivity(R"~({
			"title": "Goto Inserts",
			"name": "analysis.goto.insert",
			"role": "action",
			"description": "This analysis step places gotos.",
			"eligibility": {
				"runOnce": false,
				"auto": {}
			}
		})~", &ForceGoto);

		// Run as soon as possible.
		metaWorkflow->InsertAfter("core.function.generateLiftedIL", "analysis.goto.insert");
		Workflow::RegisterWorkflow(metaWorkflow);

		PluginCommand::RegisterForAddress("Force Goto", "Force a goto at the given address", [](const Ref<BinaryView>& view, uint64_t addr) {
			uint64_t target = 0;
			if (!GetAddressInput(target, "Provide target address", "Target address"))
				return;
			AddGoto(view, addr, target);
			for (const auto& func : view->GetAnalysisFunctionsContainingAddress(addr))
				func->Reanalyze();
		});

		return true;
	}
}