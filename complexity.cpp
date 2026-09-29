// Copyright (c) 2015-2026 Vector 35 Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

// Code complexity metrics for Function::GetComplexity. See the doc comment on that method, and
// python/complexity.py (the equivalent implementation for the Python API), for a description of
// each metric and the reasoning behind the default composite weights. The two implementations
// are intentionally kept in algorithmic lock-step; if you change one, change the other.

#include "binaryninjaapi.h"
#include "mediumlevelilinstruction.h"
#include "highlevelilinstruction.h"
#include <algorithm>
#include <cmath>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

using namespace BinaryNinja;
using namespace std;

namespace {

	// Top-level MLIL statement operations that alter control flow. Calls are intentionally
	// excluded: they don't change the shape of the *local* control flow graph, and their cost is
	// already captured by the instruction-count and instruction-diversity metrics.
	const unordered_set<BNMediumLevelILOperation> g_mlilBranchOperations = {
		MLIL_IF, MLIL_GOTO, MLIL_JUMP, MLIL_JUMP_TO,
		MLIL_TAILCALL, MLIL_TAILCALL_UNTYPED, MLIL_TAILCALL_SSA, MLIL_TAILCALL_UNTYPED_SSA
	};

	// HLIL operations that introduce a new level of structural nesting.
	const unordered_set<BNHighLevelILOperation> g_hlilNestingOperations = {
		HLIL_IF, HLIL_WHILE, HLIL_WHILE_SSA, HLIL_DO_WHILE, HLIL_DO_WHILE_SSA,
		HLIL_FOR, HLIL_FOR_SSA, HLIL_SWITCH
	};

	// MLIL call-like operations whose "dest" operand may resolve to a callee.
	const unordered_set<BNMediumLevelILOperation> g_mlilCallOperations = {
		MLIL_CALL, MLIL_CALL_UNTYPED, MLIL_CALL_SSA, MLIL_CALL_UNTYPED_SSA,
		MLIL_TAILCALL, MLIL_TAILCALL_UNTYPED, MLIL_TAILCALL_SSA, MLIL_TAILCALL_UNTYPED_SSA
	};

	// Syscalls target a syscall number, not an address - always treated as "external" (opaque).
	const unordered_set<BNMediumLevelILOperation> g_mlilSyscallOperations = {
		MLIL_SYSCALL, MLIL_SYSCALL_SSA, MLIL_SYSCALL_UNTYPED, MLIL_SYSCALL_UNTYPED_SSA
	};

	// Symbol types whose implementation isn't in this binary (imports/thunks/library stubs) - we
	// can see that a call goes there, but not what happens once it does.
	const unordered_set<BNSymbolType> g_externalSymbolTypes = {
		ImportAddressSymbol, ImportedFunctionSymbol, ExternalSymbol, LibraryFunctionSymbol
	};

	// Default weights used to blend the individual metrics into "composite". Tuned so that a
	// small, simple function scores in the single digits and a deeply nested, branchy function
	// scores in the hundreds. Callers who want different behavior should call the individual
	// metrics directly and combine them with their own weights.
	struct ComplexityWeights
	{
		double cyclomatic = 0.25;
		double instructionCount = 0.05;
		double branchDensity = 10.0;
		double halstead = 0.05;
		double nestingDepth = 2.0;
		double cognitive = 0.5;
	};


	double CyclomaticComplexity(const Function* func)
	{
		vector<Ref<BasicBlock>> blocks = func->GetBasicBlocks();
		size_t n = blocks.size();
		if (n == 0)
			return 0.0;

		size_t e = 0;
		for (auto& block : blocks)
			e += block->GetOutgoingEdges().size();

		return double((int64_t)e - (int64_t)n + 2);
	}


	double InstructionCountComplexity(const Function* func)
	{
		Ref<MediumLevelILFunction> mlil = func->GetMediumLevelIL();
		if (!mlil)
			return 0.0;

		size_t count = 0;
		mlil->VisitAllExprs([&](BasicBlock*, const MediumLevelILInstruction&) {
			count++;
			return true;
		});
		return double(count);
	}


	// Raw lexical size: total disassembly text tokens (mnemonics, operands, punctuation, ...)
	// across the function. Unlike InstructionCountComplexity, which counts semantic MLIL nodes,
	// this counts the literal tokens of the disassembly listing you'd actually read, and is
	// available even for functions without MLIL/HLIL.
	double TokenCountComplexity(const Function* func)
	{
		Ref<DisassemblySettings> settings = new DisassemblySettings();
		size_t total = 0;
		for (auto& block : func->GetBasicBlocks())
			for (auto& line : block->GetDisassemblyText(settings))
				total += line.tokens.size();
		return double(total);
	}


	double BranchDensityComplexity(const Function* func)
	{
		Ref<MediumLevelILFunction> mlil = func->GetMediumLevelIL();
		if (!mlil)
			return 0.0;

		size_t total = mlil->GetInstructionCount();
		if (total == 0)
			return 0.0;

		size_t branches = 0;
		mlil->VisitInstructions([&](BasicBlock*, const MediumLevelILInstruction& instr) {
			if (g_mlilBranchOperations.count(instr.operation))
				branches++;
		});
		return double(branches) / double(total);
	}


	string DescribeScalarOperand(const MediumLevelILOperand& operand)
	{
		ostringstream oss;
		switch (operand.GetType())
		{
		case IntegerMediumLevelOperand:
			oss << "int:" << operand.GetInteger();
			break;
		case IndexMediumLevelOperand:
			oss << "idx:" << operand.GetIndex();
			break;
		case IntrinsicMediumLevelOperand:
			oss << "intrinsic:" << operand.GetIntrinsic();
			break;
		case VariableMediumLevelOperand:
			oss << "var:" << operand.GetVariable().ToIdentifier();
			break;
		case SSAVariableMediumLevelOperand:
		{
			SSAVariable v = operand.GetSSAVariable();
			oss << "ssavar:" << v.var.ToIdentifier() << ":" << v.version;
			break;
		}
		default:
			// ConstantData/Constraint/ForceVersionReason and similar: not distinguishing their
			// contents is an acceptable approximation for a heuristic complexity metric.
			oss << "operand:" << (int)operand.GetType();
			break;
		}
		return oss.str();
	}


	// Halstead's operator/operand model applied to MLIL: every instruction and sub-expression is
	// an "operator" (keyed by its operation kind); every non-expression operand it reads is an
	// "operand" (keyed by its concrete value so that e.g. two different constants count as two
	// distinct operands). Sub-expressions are not counted as operands since they're already
	// counted as their own operator node.
	double HalsteadVolumeComplexity(const Function* func)
	{
		Ref<MediumLevelILFunction> mlil = func->GetMediumLevelIL();
		if (!mlil)
			return 0.0;

		unordered_map<BNMediumLevelILOperation, size_t> operators;
		unordered_map<string, size_t> operands;

		mlil->VisitAllExprs([&](BasicBlock*, const MediumLevelILInstruction& instr) {
			operators[instr.operation]++;
			for (auto& operand : instr.GetOperands())
			{
				switch (operand.GetType())
				{
				case ExprMediumLevelOperand:
				case ExprListMediumLevelOperand:
					break;
				case VariableListMediumLevelOperand:
					for (auto& v : operand.GetVariableList())
						operands[string("var:") + to_string(v.ToIdentifier())]++;
					break;
				case SSAVariableListMediumLevelOperand:
					for (auto& v : operand.GetSSAVariableList())
						operands[string("ssavar:") + to_string(v.var.ToIdentifier()) + ":" + to_string(v.version)]++;
					break;
				case IndexListMediumLevelOperand:
					for (auto i : operand.GetIndexList())
						operands[string("idx:") + to_string(i)]++;
					break;
				default:
					operands[DescribeScalarOperand(operand)]++;
					break;
				}
			}
			return true;
		});

		size_t distinctOperators = operators.size();
		size_t distinctOperands = operands.size();

		size_t totalOperators = 0;
		for (auto& entry : operators)
			totalOperators += entry.second;

		size_t totalOperands = 0;
		for (auto& entry : operands)
			totalOperands += entry.second;

		size_t vocabulary = distinctOperators + distinctOperands;
		size_t length = totalOperators + totalOperands;
		if (vocabulary <= 1)
			return 0.0;

		return double(length) * log2(double(vocabulary));
	}


	double NestingDepthComplexity(const Function* func)
	{
		Ref<HighLevelILFunction> hlil = func->GetHighLevelIL();
		if (!hlil)
			return 0.0;

		size_t currentDepth = 0;
		size_t maxDepth = 0;
		hlil->GetRootExpr().VisitExprs(
			[&](const HighLevelILInstruction& expr) -> bool {
				if (g_hlilNestingOperations.count(expr.operation))
				{
					currentDepth++;
					maxDepth = std::max(maxDepth, currentDepth);
				}
				return true;
			},
			[&](const HighLevelILInstruction& expr) {
				if (g_hlilNestingOperations.count(expr.operation))
					currentDepth--;
			});

		return double(maxDepth);
	}


	// Simplified SonarSource-style cognitive complexity: every control-flow-breaking construct
	// costs 1 point, plus 1 additional point for every level of nesting it sits inside. This
	// penalizes deeply nested logic more than the same number of branches laid out flat, unlike
	// cyclomatic complexity which treats them identically.
	double CognitiveComplexity(const Function* func)
	{
		Ref<HighLevelILFunction> hlil = func->GetHighLevelIL();
		if (!hlil)
			return 0.0;

		double score = 0.0;
		size_t nesting = 0;
		hlil->GetRootExpr().VisitExprs(
			[&](const HighLevelILInstruction& expr) -> bool {
				if (g_hlilNestingOperations.count(expr.operation))
				{
					score += 1.0 + double(nesting);
					nesting++;
				}
				return true;
			},
			[&](const HighLevelILInstruction& expr) {
				if (g_hlilNestingOperations.count(expr.operation))
					nesting--;
			});

		return score;
	}


	struct CallSites
	{
		// One entry per call site that resolves to a function defined in this binary (duplicates
		// included, e.g. the same helper called twice shows up twice).
		vector<Ref<Function>> internalCallees;
		size_t externalCount = 0;
		size_t indirectCount = 0;
	};


	// Walks every call-like MLIL statement in `func` and sorts it into one of three buckets:
	//
	// * resolves to a function defined in this binary -> appended to internalCallees
	// * resolves to an address, but that address is an import/thunk/library stub, or analysis
	//   couldn't identify a function there -> externalCount
	// * the target isn't a static constant at all (computed/register call, e.g. through a
	//   function pointer or vtable) -> indirectCount, since we can't know what runs there without
	//   deeper (and possibly incomplete) analysis
	CallSites ClassifyCallSites(const Function* func)
	{
		CallSites result;

		Ref<MediumLevelILFunction> mlil = func->GetMediumLevelIL();
		if (!mlil)
			return result;

		Ref<BinaryView> view = func->GetView();

		mlil->VisitInstructions([&](BasicBlock*, const MediumLevelILInstruction& instr) {
			if (g_mlilSyscallOperations.count(instr.operation))
			{
				result.externalCount++;
				return;
			}
			if (!g_mlilCallOperations.count(instr.operation))
				return;

			bool foundDest = false;
			MediumLevelILInstruction dest;
			for (auto& operand : instr.GetOperands())
			{
				if (operand.GetUsage() == DestExprMediumLevelOperandUsage && operand.GetType() == ExprMediumLevelOperand)
				{
					dest = operand.GetExpr();
					foundDest = true;
					break;
				}
			}

			if (!foundDest ||
				(dest.operation != MLIL_CONST && dest.operation != MLIL_CONST_PTR && dest.operation != MLIL_IMPORT))
			{
				result.indirectCount++;
				return;
			}

			uint64_t targetAddr = dest.GetRawOperandAsInteger(0);
			vector<Ref<Function>> targets = view->GetAnalysisFunctionsForAddress(targetAddr);
			if (targets.empty())
			{
				result.externalCount++;
				return;
			}

			Ref<Symbol> symbol = view->GetSymbolByAddress(targetAddr);
			if (symbol && g_externalSymbolTypes.count(symbol->GetType()))
				result.externalCount++;
			else
				result.internalCallees.push_back(targets[0]);
		});

		return result;
	}


	// How much, and how riskily, `func` fans out into other code - captures the "main() is just a
	// dispatcher" shape that every intraprocedural metric above misses. Distinct callees count in
	// full; repeated calls to a callee already counted (e.g. in a loop) count for less. Calls to
	// external/library code count more, since we can't inspect what they do. Indirect calls count
	// the most, since we can't even statically know what runs.
	double FanOutComplexity(const Function* func)
	{
		CallSites calls = ClassifyCallSites(func);

		unordered_set<uint64_t> distinctTargets;
		for (auto& callee : calls.internalCallees)
			distinctTargets.insert(callee->GetStart());

		size_t repeatCalls = calls.internalCallees.size() - distinctTargets.size();

		return double(distinctTargets.size()) +
			0.25 * double(repeatCalls) +
			1.5 * double(calls.externalCount) +
			2.5 * double(calls.indirectCount);
	}


	double CompositeComplexity(const Function* func);


	// `func`'s own composite complexity plus the (decayed) composite complexity of everything it
	// calls, recursively, up to maxDepth hops. This is the metric that actually answers "this
	// function looks simple, but how much do I have to read to understand what it does": a
	// function with a low `composite` score but a high `transitive` score is exactly a thin
	// dispatcher over a lot of real work.
	//
	// Each function is only ever counted once (tracked by start address) across the whole walk,
	// which both breaks recursion/cycles safely and avoids over-counting a shared helper reached
	// through multiple paths - once you've read it, you don't need to read it again for a sibling
	// call.
	double TransitiveComplexityWalk(const Function* func, size_t depth, double decay, unordered_set<uint64_t>& visited)
	{
		if (visited.count(func->GetStart()))
			return 0.0;
		visited.insert(func->GetStart());

		double total = CompositeComplexity(func);
		if (depth == 0)
			return total;

		unordered_map<uint64_t, Ref<Function>> callees;
		for (auto& callee : ClassifyCallSites(func).internalCallees)
			callees.emplace(callee->GetStart(), callee);

		for (auto& entry : callees)
			total += decay * TransitiveComplexityWalk(entry.second, depth - 1, decay, visited);

		return total;
	}


	double TransitiveComplexity(const Function* func)
	{
		const size_t maxDepth = 2;
		const double decay = 0.5;
		unordered_set<uint64_t> visited;
		return TransitiveComplexityWalk(func, maxDepth, decay, visited);
	}


	double CompositeComplexity(const Function* func)
	{
		static const ComplexityWeights weights;
		return weights.cyclomatic * CyclomaticComplexity(func) +
			weights.instructionCount * InstructionCountComplexity(func) +
			weights.branchDensity * BranchDensityComplexity(func) +
			weights.halstead * HalsteadVolumeComplexity(func) +
			weights.nestingDepth * NestingDepthComplexity(func) +
			weights.cognitive * CognitiveComplexity(func);
	}

}  // namespace


double Function::GetComplexity(const string& metric) const
{
	if (metric == "cyclomatic")
		return CyclomaticComplexity(this);
	if (metric == "instruction_count")
		return InstructionCountComplexity(this);
	if (metric == "token_count")
		return TokenCountComplexity(this);
	if (metric == "branch_density")
		return BranchDensityComplexity(this);
	if (metric == "halstead")
		return HalsteadVolumeComplexity(this);
	if (metric == "nesting_depth")
		return NestingDepthComplexity(this);
	if (metric == "cognitive")
		return CognitiveComplexity(this);
	if (metric == "composite")
		return CompositeComplexity(this);
	if (metric == "fan_out")
		return FanOutComplexity(this);
	if (metric == "transitive")
		return TransitiveComplexity(this);

	throw std::invalid_argument("Unknown complexity metric \"" + metric + "\"; valid options are: " +
		"cyclomatic, instruction_count, token_count, branch_density, halstead, nesting_depth, cognitive, "
		"composite, fan_out, transitive");
}


vector<string> Function::GetComplexityMetricNames()
{
	return {"cyclomatic", "instruction_count", "token_count", "branch_density", "halstead", "nesting_depth",
		"cognitive", "composite", "fan_out", "transitive"};
}
