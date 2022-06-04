#pragma once
#include <vector>
#include <string>
#include "database.h"
#include "user.hpp"

namespace BinaryNinja {
    struct InstructionTextToken;

	struct UndoAction
	{
		BNActionType actionType;
		std::string summaryText;
		std::vector<InstructionTextToken> summaryTokens;

		UndoAction() {};
		UndoAction(const BNUndoAction& action);
	};

	struct UndoEntry
	{
		Ref<User> user;
		std::string hash;
		std::vector<UndoAction> actions;
		uint64_t timestamp;
	};
}