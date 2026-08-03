#include "processor.h"

#include "third_party/absl/container/flat_hash_set.h"
#include "third_party/absl/strings/ascii.h"
#include "third_party/zynamics/binexport/basic_block.h"
#include "third_party/zynamics/binexport/binexport2_writer.h"
#include "third_party/zynamics/binexport/call_graph.h"
#include "third_party/zynamics/binexport/flow_graph.h"
#include "third_party/zynamics/binexport/instruction.h"
#include "third_party/zynamics/binexport/util/filesystem.h"
#include "third_party/zynamics/binexport/address_references.h"

#include <mutex>

using namespace security::binexport;

namespace {
	std::mutex g_instructionStateMutex;

	int GetSegmentPermissions(const BinaryNinja::Segment& segment)
	{
		int permissions = 0;
		const uint32_t segment_flags = segment.GetFlags();
		if (segment_flags & SegmentExecutable)
			permissions |= AddressSpace::kExecute;
		if (segment_flags & SegmentWritable)
			permissions |= AddressSpace::kWrite;
		if (segment_flags & SegmentReadable)
			permissions |= AddressSpace::kRead;
		return permissions;
	}

	std::optional<size_t> FindMnemonic(const std::vector<BinaryNinja::InstructionTextToken>& instrTokens)
	{
		for (size_t i = 0; i < instrTokens.size(); i++)
		{
			if (instrTokens[i].type == InstructionToken)
				return i;
		}
		return std::nullopt;
	}

	Instruction ParseInstructionBinaryNinja(uint64_t address, const BinaryNinja::InstructionInfo& instruction,
		const std::vector<BinaryNinja::InstructionTextToken>& instrTokens)
	{
		const auto mnemonicIndex = FindMnemonic(instrTokens);
		if (!mnemonicIndex)
			return Instruction(address);
		std::string mnemonic = instrTokens[*mnemonicIndex].text;
		absl::StripAsciiWhitespace(&mnemonic);

		const Address nextInstrAddr = address + instruction.length;
		return Instruction(address, nextInstrAddr, instruction.length, mnemonic, {});
	}
}  // namespace

struct BinDiffProcessor::Impl
{
	struct BasicBlockRange
	{
		Address start;
		Address end;
	};

	struct FunctionTopology
	{
		Address entryPoint;
		std::vector<BasicBlockRange> basicBlocks;
		std::vector<FlowGraphEdge> flowEdges;
		std::vector<std::pair<Address, Address>> callEdges;
	};

	std::unique_lock<std::mutex> m_instructionStateLock {g_instructionStateMutex};
	BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;
	AddressReferences m_addressReferences;
	AddressSpace m_addressSpace;
	AddressSpace m_flagSpace;
	std::unique_ptr<CallGraph> m_callGraph;
	std::unique_ptr<FlowGraph> m_flowGraph;
	Instructions m_instructions;
	std::vector<FunctionTopology> m_functionTopologies;
	absl::flat_hash_set<Address> m_functionStarts;
};


BinDiffProcessor::BinDiffProcessor(BinaryNinja::BinaryView& view)
{
	m_impl = std::make_unique<Impl>();
	m_impl->m_view = &view;
	m_impl->m_addressReferences = {};
	m_impl->m_addressSpace = {};
	m_impl->m_flagSpace = {};
	m_impl->m_callGraph = std::make_unique<CallGraph>();
	m_impl->m_flowGraph = std::make_unique<FlowGraph>();
	m_impl->m_instructions = {};
	for (const auto& function : view.GetAnalysisFunctionList())
		m_impl->m_functionStarts.insert(function->GetStart());

	for (const auto& segment : view.GetSegments())
	{
		const uint64_t segmentAddr = segment->GetStart();
		const uint64_t segmentLen = segment->GetLength();
		const int permissions = GetSegmentPermissions(*segment);

		// Map the segment without reading its contents.
		m_impl->m_flagSpace.AddMemoryBlock(segmentAddr, AddressSpace::MemoryBlock(segmentLen), permissions);
	}

	const auto architecture = view.GetDefaultArchitecture();
	const int bitness = architecture ? static_cast<int>(architecture->GetAddressSize()) * 8 : 32;
	Instruction::SetBitness(bitness);
	Instruction::SetMemoryFlags(&m_impl->m_flagSpace);
}

BinDiffProcessor::~BinDiffProcessor()
{
	Instruction::SetGetBytesCallback({});
	Instruction::SetMemoryFlags(nullptr);
	Operand::EmptyCache();
	Expression::EmptyCache();
}

void BinDiffProcessor::AddFunction(BinaryNinja::Function& func)
{
	BinaryNinja::Ref<BinaryNinja::BinaryView> view = func.GetView();
	const auto basicBlocks = func.GetBasicBlocks();
	auto& topology = m_impl->m_functionTopologies.emplace_back();
	topology.entryPoint = func.GetStart();
	topology.basicBlocks.reserve(basicBlocks.size());
	std::vector<Address> basicBlockStarts;
	basicBlockStarts.reserve(basicBlocks.size());
	for (const auto& block : basicBlocks)
	{
		basicBlockStarts.push_back(block->GetStart());
		topology.basicBlocks.push_back({block->GetStart(), block->GetEnd()});
	}
	std::sort(basicBlockStarts.begin(), basicBlockStarts.end());

	m_impl->m_callGraph->AddFunction(func.GetStart());

	Instruction::SetGetBytesCallback([view](const Instruction& instr) -> std::string {
		const BinaryNinja::DataBuffer buffer = view->ReadBuffer(instr.GetAddress(), instr.GetSize());
		const size_t length = buffer.GetLength();
		if (length == 0)
			return {};
		return {static_cast<const char*>(buffer.GetData()), length};
	});

	auto ProcessInstruction = [this, view, &func, &basicBlockStarts, &topology](
		const BinaryNinja::InstructionInfo& instrInfo, Instruction& instr) {
		const uint64_t instrAddr = instr.GetAddress();
		// TODO: Really dumb optimization to get some large binaries to finish in time.
		// TODO: I am sure there is a better way to express this but I think we punt on that for now.
		const auto isOwnedBlock = [&](const Address address) {
			return std::ranges::binary_search(basicBlockStarts, address);
		};
		bool isUnresolvedBranch = false;
		bool isFallthrough = instrInfo.branchCount == 0;
		for (int branchIdx = 0; branchIdx < instrInfo.branchCount; branchIdx++)
		{
			const uint64_t branchTarget = instrInfo.branchTarget[branchIdx];
			switch (instrInfo.branchType[branchIdx])
			{
			case IndirectBranch:
				if ((branchTarget != 0) && isOwnedBlock(branchTarget))
					topology.flowEdges.emplace_back(instrAddr, branchTarget, FlowGraphEdge::TYPE_UNCONDITIONAL);
				break;
			case UnconditionalBranch:
			case UserDefinedBranch:
			case ExceptionBranch:
				if (branchTarget != 0)
				{
					if (!isOwnedBlock(branchTarget))
					{
						if (m_impl->m_functionStarts.contains(branchTarget))
						{
							m_impl->m_callGraph->AddFunction(branchTarget);
							topology.callEdges.emplace_back(instrAddr, branchTarget);
							instr.SetFlag(FLAG_CALL, true);
							m_impl->m_addressReferences.emplace_back(
								instrAddr, GetSourceExpressionId(instr, branchTarget), branchTarget, TYPE_CALL_DIRECT);
						}
						break;
					}
					topology.flowEdges.emplace_back(instrAddr, branchTarget, FlowGraphEdge::TYPE_UNCONDITIONAL);
				}
				break;
			case CallDestination:
				if (m_impl->m_functionStarts.contains(branchTarget))
				{
					m_impl->m_callGraph->AddFunction(branchTarget);
					topology.callEdges.emplace_back(instrAddr, branchTarget);
				}
				ABSL_FALLTHROUGH_INTENDED;
			case SystemCall:
				instr.SetFlag(FLAG_CALL, true);
				m_impl->m_addressReferences.emplace_back(
					instrAddr, GetSourceExpressionId(instr, branchTarget), branchTarget, TYPE_CALL_DIRECT);
				isFallthrough = true;
				break;
			case TrueBranch:
				if (!isOwnedBlock(branchTarget))
					break;
				topology.flowEdges.emplace_back(instrAddr, branchTarget, FlowGraphEdge::TYPE_TRUE);
				break;
			case FalseBranch:
				if (!isOwnedBlock(branchTarget))
					break;
				topology.flowEdges.emplace_back(instrAddr, branchTarget, FlowGraphEdge::TYPE_FALSE);
				break;
			case FunctionReturn:
				break;
			case UnresolvedBranch:
				isUnresolvedBranch = true;
				break;
			default:
				break;
			}
		}

		instr.SetFlag(FLAG_FLOW, isFallthrough);

		if (isUnresolvedBranch)
		{
			BinaryNinja::ReferenceSource refSource = {&func, func.GetArchitecture(), instrAddr};
			for (const auto& xref : view->GetCodeReferencesFrom(refSource))
			{
				if (!isOwnedBlock(xref))
					continue;
				topology.flowEdges.emplace_back(instrAddr, xref, FlowGraphEdge::TYPE_SWITCH);
			}
		}
	};

	BinaryNinja::InstructionInfo instrInfo = {};
	uint8_t instrData[BN_MAX_INSTRUCTION_LENGTH] = {};
	std::vector<BinaryNinja::InstructionTextToken> instrTokens = {};
	instrTokens.reserve(10);

	for (const auto& block : basicBlocks)
	{
		const auto blockArch = block->GetArchitecture();
		const size_t maxInstrLen = blockArch->GetMaxInstructionLength();
		uint64_t instrAddr = block->GetStart();

		while (instrAddr < block->GetEnd())
		{
			const size_t bufferLen = view->Read(instrData, instrAddr, maxInstrLen);
			if ((bufferLen == 0) || !blockArch->GetInstructionInfo(instrData, instrAddr, bufferLen, instrInfo))
				break;
			instrTokens.clear();
			if (!blockArch->GetInstructionText(instrData, instrAddr, instrInfo.length, instrTokens))
				break;

			Instruction instrBd = ParseInstructionBinaryNinja(instrAddr, instrInfo, instrTokens);
			ProcessInstruction(instrInfo, instrBd);
			m_impl->m_instructions.push_back(instrBd);
			instrAddr += instrInfo.length;
		}
	}
}

bool BinDiffProcessor::Process(const std::string& exportFilePath, std::function<bool(double)> progress)
{
	if (!progress(0.0))
		return false;
	SortInstructions(&m_impl->m_instructions);
	m_impl->m_instructions.erase(std::unique(m_impl->m_instructions.begin(), m_impl->m_instructions.end(),
		[](const Instruction& left, const Instruction& right) { return left.GetAddress() == right.GetAddress(); }),
		m_impl->m_instructions.end());
	if (!progress(0.05))
		return false;

	std::sort(m_impl->m_addressReferences.begin(), m_impl->m_addressReferences.end());
	m_impl->m_addressReferences.erase(
		std::unique(m_impl->m_addressReferences.begin(), m_impl->m_addressReferences.end()),
		m_impl->m_addressReferences.end());
	if (!progress(0.1))
		return false;

	std::vector<Address> blockBoundaries;
	for (const auto& topology : m_impl->m_functionTopologies)
	{
		for (const auto& block : topology.basicBlocks)
		{
			blockBoundaries.push_back(block.start);
			blockBoundaries.push_back(block.end);
		}
	}
	std::sort(blockBoundaries.begin(), blockBoundaries.end());
	blockBoundaries.erase(std::unique(blockBoundaries.begin(), blockBoundaries.end()), blockBoundaries.end());

	auto& functions = m_impl->m_flowGraph->GetFunctions();
	for (size_t topologyIndex = 0; topologyIndex < m_impl->m_functionTopologies.size(); ++topologyIndex)
	{
		if (((topologyIndex & 0x3ff) == 0) && !progress(0.1
				+ (0.55 * static_cast<double>(topologyIndex) / m_impl->m_functionTopologies.size())))
			return false;

		const auto& topology = m_impl->m_functionTopologies[topologyIndex];
		auto function = std::make_unique<Function>(topology.entryPoint);
		std::vector<FlowGraphEdge> edges = topology.flowEdges;
		bool hasEntryBlock = false;

		for (const auto& block : topology.basicBlocks)
		{
			auto boundary = std::upper_bound(blockBoundaries.begin(), blockBoundaries.end(), block.start);
			Address segmentStart = block.start;
			BasicBlock* previousBlock = nullptr;
			while (segmentStart < block.end)
			{
				const Address segmentEnd = boundary != blockBoundaries.end() && *boundary < block.end
					? *boundary
					: block.end;
				auto instruction = GetInstruction(&m_impl->m_instructions, segmentStart);
				BasicBlockInstructions blockInstructions;
				while (instruction != m_impl->m_instructions.end() && instruction->GetAddress() < segmentEnd)
				{
					blockInstructions.AddInstruction(instruction);
					++instruction;
				}

				BasicBlock* basicBlock = BasicBlock::Find(segmentStart);
				if (!basicBlock)
					basicBlock = BasicBlock::Create(&blockInstructions);
				if (basicBlock)
				{
					function->AddBasicBlock(basicBlock);
					hasEntryBlock |= basicBlock->GetEntryPoint() == topology.entryPoint;
					if (previousBlock)
						edges.emplace_back(previousBlock->GetLastAddress(), basicBlock->GetEntryPoint(),
							FlowGraphEdge::TYPE_UNCONDITIONAL);
					previousBlock = basicBlock;
				}

				segmentStart = segmentEnd;
				if (boundary != blockBoundaries.end() && *boundary == segmentEnd)
					++boundary;
			}
		}

		std::sort(edges.begin(), edges.end());
		edges.erase(std::unique(edges.begin(), edges.end()), edges.end());
		for (const auto& edge : edges)
			function->AddEdge(edge);
		function->SortGraph();
		size_t instructionCount = 0;
		for (const auto* basicBlock : function->GetBasicBlocks())
			instructionCount += basicBlock->GetInstructionCount();

		if (!hasEntryBlock || function->GetBasicBlocks().size() >= FlowGraph::kMaxFunctionBasicBlocks
			|| function->GetEdges().size() >= FlowGraph::kMaxFunctionEdges
			|| instructionCount >= FlowGraph::kMaxFunctionInstructions)
		{
			function->Clear();
			function->SetType(Function::TYPE_INVALID);
		}
		else
		{
			for (const auto& [source, target] : topology.callEdges)
				m_impl->m_callGraph->ScheduleEdgeAdd(function.get(), source, target);
		}

		const bool inserted = functions.emplace(topology.entryPoint, function.get()).second;
		assert(inserted);
		(void)inserted;
		function.release();
	}

	for (const Address entryPoint : m_impl->m_callGraph->GetFunctions())
	{
		if (functions.find(entryPoint) == functions.end())
			functions.emplace(entryPoint, new Function(entryPoint));
	}
	m_impl->m_callGraph->CommitEdges();
	if (!progress(0.65))
		return false;

	m_impl->m_flowGraph->PruneFlowGraphEdges();
	m_impl->m_callGraph->PostProcessComments();
	if (!progress(0.7))
		return false;

	size_t functionIndex = 0;
	for (const auto& [address, function] : functions)
	{
		if (((functionIndex++ & 0x3ff) == 0)
			&& !progress(0.7 + (0.1 * static_cast<double>(functionIndex) / functions.size())))
			return false;
		BinaryNinja::Ref<BinaryNinja::Symbol> funcSym = m_impl->m_view->GetSymbolByAddress(address);
		if (!funcSym)
			funcSym = new BinaryNinja::Symbol(FunctionSymbol, fmt::format("func_{:x}", address), address);
		function->SetName(funcSym->GetRawName(), funcSym->GetShortName());

		if (funcSym->GetType() == ImportedFunctionSymbol)
		{
			function->SetType(Function::TYPE_IMPORTED);
		}
		else if (function->GetType() == Function::TYPE_NONE || function->GetTypeHeuristic() == Function::TYPE_STANDARD)
		{
			if (function->GetBasicBlocks().empty())
				function->SetType(Function::TYPE_IMPORTED);
			else
				function->SetType(Function::TYPE_STANDARD);
		}
	}

	const std::string placeholderSha256(64, '0');
	const auto architecture = m_impl->m_view->GetDefaultArchitecture();
	const std::string architectureName = architecture ? architecture->GetName() : "unknown";

	BinExport2Writer writer(
		exportFilePath, m_impl->m_view->GetFile()->GetOriginalFilename(), placeholderSha256, architectureName);
	if (!progress(0.85))
		return false;

	auto status = writer.Write(*m_impl->m_callGraph, *m_impl->m_flowGraph, m_impl->m_instructions,
		m_impl->m_addressReferences, m_impl->m_addressSpace);

	if (!status.ok())
	{
		BinaryNinja::LogErrorF("Failed to export BinDiff data: {}", status.message());
		return false;
	}
	return progress(1.0);
}
