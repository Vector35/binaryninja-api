#pragma once

#include "binaryninjacore.h"
#include "refcount.h"
#include <string>
#include <vector>

namespace BinaryNinja
{
	struct InstructionTextToken;
	/*!

		\ingroup undo
	*/
	class UndoAction : public CoreRefCountObject<BNUndoAction, BNNewUndoActionReference, BNFreeUndoAction>
	{
	  public:
		UndoAction(BNUndoAction* action);

		std::string GetSummaryText();
		std::vector<InstructionTextToken> GetSummary();
	};

	/*!

		\ingroup undo
	*/
	class UndoEntry : public CoreRefCountObject<BNUndoEntry, BNNewUndoEntryReference, BNFreeUndoEntry>
	{
	  public:
		UndoEntry(BNUndoEntry* entry);

		std::string GetId();
		std::vector<Ref<UndoAction>> GetActions();
		uint64_t GetTimestamp();
	};

}
