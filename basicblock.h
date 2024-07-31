#pragma once

#include "binaryninjacore.h"
#include "refcount.h"
#include <set>
#include <vector>

namespace BinaryNinja
{

	class Architecture;
	class BasicBlock;
	class DisassemblySettings;
	struct DisassemblyTextLine;
	class Function;
	struct InstructionTextToken;
	class HighLevelILFunction;
	class LowLevelILFunction;
	class MediumLevelILFunction;

	/*!
		\ingroup basicblocks
	*/
	struct BasicBlockEdge
	{
		BNBranchType type;
		Ref<BasicBlock> target; //! The source or destination of the edge, depending on context
		bool backEdge;
		bool fallThrough;
	};

	/*!
		\ingroup basicblocks
	*/
	class BasicBlock : public CoreRefCountObject<BNBasicBlock, BNNewBasicBlockReference, BNFreeBasicBlock>
	{
	  public:
		BasicBlock(BNBasicBlock* block);

		/*! Basic block function

			\return The Function for this basic block
		*/
		Ref<Function> GetFunction() const;

		/*! Basic block architecture

			\return The Architecture for this Basic Block
		*/
		Ref<Architecture> GetArchitecture() const;

		/*! Starting address of the basic block

			\return Start address of the basic block
		*/
		uint64_t GetStart() const;

		/*! Ending address of the basic block

			\return Ending address of the basic block
		*/
		uint64_t GetEnd() const;

		/*! Length of the basic block

			\return Length of the basic block
		*/
		uint64_t GetLength() const;

		/*! Basic block index in list of blocks for the function

			\return Basic block index in list of blocks for the function
		*/
		size_t GetIndex() const;

		/*! List of basic block outgoing edges

			\return List of basic block outgoing edges
		*/
		std::vector<BasicBlockEdge> GetOutgoingEdges() const;

		/*! List of basic block incoming edges

			\return List of basic block incoming edges
		*/
		std::vector<BasicBlockEdge> GetIncomingEdges() const;

		/*! Whether basic block has undetermined outgoing edges

			\return Whether basic block has undetermined outgoing edges
		*/
		bool HasUndeterminedOutgoingEdges() const;

		/*! Whether basic block can return or is tagged as 'No Return'

			\return Whether basic block can return or is tagged as 'No Return'
		*/
		bool CanExit() const;

		/*! Sets whether basic block can return or is tagged as 'No Return'

			\param value Sets whether basic block can return or is tagged as 'No Return'
		*/
		void SetCanExit(bool value);

		/*! List of dominators for this basic block

			\param post Whether to get post dominators (default: false)
			\return Set of BasicBlock dominators
		*/
		std::set<Ref<BasicBlock>> GetDominators(bool post = false) const;

		/*! List of dominators for this basic block

			\param post Whether to get post dominators (default: false)
			\return Set of BasicBlock dominators
		*/
		std::set<Ref<BasicBlock>> GetStrictDominators(bool post = false) const;

		/*! Get the immediate dominator of this basic block

			\param post Whether to get the immediate post dominator
			\return Immediate dominator basic block
		*/
		Ref<BasicBlock> GetImmediateDominator(bool post = false) const;

		/*! List of child blocks in the dominator tree for this basic block

			\param post Whether to get the post dominator tree children
			\return Set of Tree children
		*/
		std::set<Ref<BasicBlock>> GetDominatorTreeChildren(bool post = false) const;

		/*! Get the dominance frontier for this basic block

			\param post Whether to get the post dominance frontier
			\return Post dominance frontier for this basic block
		*/
		std::set<Ref<BasicBlock>> GetDominanceFrontier(bool post = false) const;
		static std::set<Ref<BasicBlock>> GetIteratedDominanceFrontier(const std::set<Ref<BasicBlock>>& blocks);

		void MarkRecentUse();

		/*! List of automatic annotations for the start of this block

			\return List of automatic annotations for the start of this block
		*/
		std::vector<std::vector<InstructionTextToken>> GetAnnotations();

		/*! property which returns a list of DisassemblyTextLine objects for the current basic block.

			\param settings Disassembly settings to use when fetching the text
			\return Disassembly text
		*/
		std::vector<DisassemblyTextLine> GetDisassemblyText(DisassemblySettings* settings);

		/*! Get the current highlight color for the Basic Block

			\return The current highlight color for the Basic Block
		*/
		BNHighlightColor GetBasicBlockHighlight();

		/*! Set the analysis basic block highlight color

			\param color Highlight Color
		*/
		void SetAutoBasicBlockHighlight(BNHighlightColor color);

		/*! Set the analysis basic block highlight color

			\param color Highlight Color
			\param alpha Transparency for the color
		*/
		void SetAutoBasicBlockHighlight(BNHighlightStandardColor color, uint8_t alpha = 255);

		/*! Set the analysis basic block highlight color

			\param color Highlight Color
			\param mixColor Highlight Color to mix with `color`
			\param mix Mix point
			\param alpha Transparency of the colors
		*/
		void SetAutoBasicBlockHighlight(
		    BNHighlightStandardColor color, BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha = 255);

		/*! Set the analysis basic block highlight color

			\param r Red value, 0-255
			\param g Green value, 0-255
			\param b Blue value, 0-255
			\param alpha Transparency of the color
		*/
		void SetAutoBasicBlockHighlight(uint8_t r, uint8_t g, uint8_t b, uint8_t alpha = 255);

		/*! Set the basic block highlight color

			\param color Highlight color
		*/
		void SetUserBasicBlockHighlight(BNHighlightColor color);

		/*! Set the basic block highlight color

			\param color Highlight color
			\param alpha Transparency of the color
		*/
		void SetUserBasicBlockHighlight(BNHighlightStandardColor color, uint8_t alpha = 255);

		/*! Set the basic block highlight color

			\param color Highlight Color
			\param mixColor Highlight Color to mix with `color`
			\param mix Mix point
			\param alpha Transparency of the colors
		*/
		void SetUserBasicBlockHighlight(
		    BNHighlightStandardColor color, BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha = 255);

		/*! Set the basic block highlight color

			\param r Red value, 0-255
			\param g Green value, 0-255
			\param b Blue value, 0-255
			\param alpha Transparency of the color
		*/
		void SetUserBasicBlockHighlight(uint8_t r, uint8_t g, uint8_t b, uint8_t alpha = 255);

		static bool IsBackEdge(BasicBlock* source, BasicBlock* target);

		/*! Whether the basic block contains IL

			\return Whether the basic block contains IL
		*/
		bool IsILBlock() const;

		/*! Whether the basic block contains Medium Level IL

			\return Whether the basic block contains Medium Level IL
		*/
		bool IsLowLevelILBlock() const;

		/*! Whether the basic block contains High Level IL

			\return Whether the basic block contains High Level IL
		*/
		bool IsMediumLevelILBlock() const;

		/*! Get the Low Level IL Function for this basic block

			\return Get the Low Level IL Function for this basic block
		*/
		Ref<LowLevelILFunction> GetLowLevelILFunction() const;

		/*! Get the Medium Level IL Function for this basic block

			\return Get the Medium Level IL Function for this basic block
		*/
		Ref<MediumLevelILFunction> GetMediumLevelILFunction() const;

		/*! Get the High Level IL Function for this basic block

			\return Get the High Level IL Function for this basic block
		*/
		Ref<HighLevelILFunction> GetHighLevelILFunction() const;

		bool GetInstructionContainingAddress(uint64_t addr, uint64_t* start);

		/*! Gets the corresponding assembly-level basic block for this basic block
			(which is itself, if called on an assembly-level basic block).

			\return Basic Block
		*/
		Ref<BasicBlock> GetSourceBlock() const;
	};
}
