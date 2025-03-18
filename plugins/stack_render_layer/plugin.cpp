
#include <binaryninjaapi.h>
#include <thread>

using namespace BinaryNinja;


class StackRenderLayer: public RenderLayer
{
public:
	StackRenderLayer(): RenderLayer("Annotate Stack Offset") {}

	void ApplyToLines(
		Ref<BasicBlock> block,
		std::vector<DisassemblyTextLine>& lines
	)
	{
		for (auto& line: lines)
		{
			// Skip blank lines (block separators)
			if (line.tokens.empty())
			{
				continue;
			}

			// Insert tokens after the address separator
			int64_t sep = -1;
			for (int64_t i = 0; i < line.tokens.size(); i ++)
			{
				if (line.tokens[i].type == AddressSeparatorToken)
				{
					sep = i;
					break;
				}
			}
			// Don't annotate lines which don't have an address separator
			// (these are usually annotations like { Does not return }
			if (sep == -1)
			{
				continue;
			}

			// Grab stack offset value from function
			auto stackOffset = block->GetFunction()->GetRegisterValueAtInstruction(
				block->GetArchitecture(),
				line.addr,
				block->GetArchitecture()->GetStackPointerRegister()
			);
			auto stackOffsetAfter = block->GetFunction()->GetRegisterValueAfterInstruction(
				block->GetArchitecture(),
				line.addr,
				block->GetArchitecture()->GetStackPointerRegister()
			);
			if (stackOffset.state == StackFrameOffset)
			{
				// Stack pointer is resolved to an offset: show the offset
				// (but negative because that is how other tools do it)
				line.tokens.emplace(
					line.tokens.begin() + sep + 1,
					IntegerToken,
					fmt::format("{:4x}", -stackOffset.value),
					-stackOffset.value
				);
			}
			else
			{
				// Stack pointer is not resolved, show ??
				line.tokens.emplace(
					line.tokens.begin() + sep + 1,
					IntegerToken,
					"  ??",
					0
				);
			}
			// And put a spacer after the offset token
			if (stackOffset != stackOffsetAfter)
			{
				line.tokens.emplace(
					line.tokens.begin() + sep + 2,
					TextToken,
					"* "
				);
			}
			else
			{
				line.tokens.emplace(
					line.tokens.begin() + sep + 2,
					TextToken,
					"  "
				);
			}
		}
	}

	virtual void ApplyToDisassemblyBlock(
		Ref<BasicBlock> block,
		std::vector<DisassemblyTextLine>& lines
	) override
	{
		// Break this out into a helper so we don't have to write it twice
		ApplyToLines(block, lines);
	}

	virtual void ApplyToLowLevelILBlock(
		Ref<BasicBlock> block,
		std::vector<DisassemblyTextLine>& lines
	) override
	{
		// Break this out into a helper so we don't have to write it twice
		ApplyToLines(block, lines);
	}
};


extern "C" {
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		static StackRenderLayer* layer = new StackRenderLayer();
		RenderLayer::Register(layer, DisabledByDefaultRenderLayerDefaultEnableState);
		return true;
	}
}