#pragma once
#include <vector>
#include <set>
#include "basicblock.h"
#include "refcount.hpp"
#include "binaryninjaapi_new.hpp"

namespace BinaryNinja {

	class Function;
	class Architecture;
	class BasicBlock;
	class DisassemblySettings;
	class LowLevelILFunction;
	class MediumLevelILFunction;
	class HighLevelILFunction;

	struct BasicBlockEdge
	{
		BNBranchType type;
		Ref<BasicBlock> target;
		bool backEdge;
		bool fallThrough;
	};

	class BasicBlock : public CoreRefCountObject<BNBasicBlock, BNNewBasicBlockReference, BNFreeBasicBlock>
	{
	  public:
		BasicBlock(BNBasicBlock* block);

		Ref<Function> GetFunction() const;
		Ref<Architecture> GetArchitecture() const;

		uint64_t GetStart() const;
		uint64_t GetEnd() const;
		uint64_t GetLength() const;

		size_t GetIndex() const;

		std::vector<BasicBlockEdge> GetOutgoingEdges() const;
		std::vector<BasicBlockEdge> GetIncomingEdges() const;
		bool HasUndeterminedOutgoingEdges() const;
		bool CanExit() const;
		void SetCanExit(bool value);

		std::set<Ref<BasicBlock>> GetDominators(bool post = false) const;
		std::set<Ref<BasicBlock>> GetStrictDominators(bool post = false) const;
		Ref<BasicBlock> GetImmediateDominator(bool post = false) const;
		std::set<Ref<BasicBlock>> GetDominatorTreeChildren(bool post = false) const;
		std::set<Ref<BasicBlock>> GetDominanceFrontier(bool post = false) const;
		static std::set<Ref<BasicBlock>> GetIteratedDominanceFrontier(const std::set<Ref<BasicBlock>>& blocks);

		void MarkRecentUse();

		std::vector<std::vector<InstructionTextToken>> GetAnnotations();

		std::vector<DisassemblyTextLine> GetDisassemblyText(DisassemblySettings* settings);

		BNHighlightColor GetBasicBlockHighlight();
		void SetAutoBasicBlockHighlight(BNHighlightColor color);
		void SetAutoBasicBlockHighlight(BNHighlightStandardColor color, uint8_t alpha = 255);
		void SetAutoBasicBlockHighlight(
			BNHighlightStandardColor color, BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha = 255);
		void SetAutoBasicBlockHighlight(uint8_t r, uint8_t g, uint8_t b, uint8_t alpha = 255);
		void SetUserBasicBlockHighlight(BNHighlightColor color);
		void SetUserBasicBlockHighlight(BNHighlightStandardColor color, uint8_t alpha = 255);
		void SetUserBasicBlockHighlight(
			BNHighlightStandardColor color, BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha = 255);
		void SetUserBasicBlockHighlight(uint8_t r, uint8_t g, uint8_t b, uint8_t alpha = 255);

		static bool IsBackEdge(BasicBlock* source, BasicBlock* target);

		bool IsILBlock() const;
		bool IsLowLevelILBlock() const;
		bool IsMediumLevelILBlock() const;
		Ref<LowLevelILFunction> GetLowLevelILFunction() const;
		Ref<MediumLevelILFunction> GetMediumLevelILFunction() const;
		Ref<HighLevelILFunction> GetHighLevelILFunction() const;

		bool GetInstructionContainingAddress(uint64_t addr, uint64_t* start);
		Ref<BasicBlock> GetSourceBlock() const;
	};

	class DisassemblySettings :
		public CoreRefCountObject<BNDisassemblySettings, BNNewDisassemblySettingsReference, BNFreeDisassemblySettings>
	{
	  public:
		DisassemblySettings();
		DisassemblySettings(BNDisassemblySettings* settings);
		DisassemblySettings* Duplicate();

		bool IsOptionSet(BNDisassemblyOption option) const;
		void SetOption(BNDisassemblyOption option, bool state = true);

		size_t GetWidth() const;
		void SetWidth(size_t width);
		size_t GetMaximumSymbolWidth() const;
		void SetMaximumSymbolWidth(size_t width);
		size_t GetGutterWidth() const;
		void SetGutterWidth(size_t width);
	};
}