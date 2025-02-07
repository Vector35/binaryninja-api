#include <ctype.h>
#include <stack>
#include "genericformatter.h"

using namespace BinaryNinja;
using namespace std;


enum ItemType
{
	Atom,
	Comment,
	Operator,
	FieldAccessor,
	Argument,
	ArgumentSeparator,
	Statement,
	StatementSeparator,
	Group,
	Container,
	StartOfContainer,
	ContainerContents,
	EndOfContainer,
};


static string TrimString(const string& str)
{
	size_t startPos = 0;
	size_t endPos = 0;

	bool start = true;
	for (size_t i = 0; i < str.size(); i++)
	{
		if (isspace(str[i]))
		{
			if (start)
			{
				startPos = i + 1;
				endPos = i + 1;
			}
		}
		else
		{
			start = false;
			endPos = i + 1;
		}
	}

	return str.substr(startPos, endPos - startPos);
}


static string TrimLeadingWhitespace(const string& str)
{
	size_t startPos = 0;
	for (size_t i = 0; i < str.size(); i++)
	{
		if (!isspace(str[i]))
		{
			startPos = i;
			break;
		}
	}
	return str.substr(startPos);
}


static string TrimTrailingWhitespace(const string& str)
{
	if (str.empty())
		return str;

	size_t endPos = str.size();
	for (size_t i = str.size() - 1; i > 0; i--)
	{
		if (!isspace(str[i]))
		{
			endPos = i + 1;
			break;
		}
	}
	return str.substr(0, endPos);
}


static const map<string, BNOperatorPrecedence> g_operatorPrecedenceMap = {{"=", AssignmentOperatorPrecedence},
	{":=", AssignmentOperatorPrecedence}, {"+=", AssignmentOperatorPrecedence}, {"-=", AssignmentOperatorPrecedence},
	{"*=", AssignmentOperatorPrecedence}, {"/=", AssignmentOperatorPrecedence}, {"s/=", AssignmentOperatorPrecedence},
	{"u/=", AssignmentOperatorPrecedence}, {"%=", AssignmentOperatorPrecedence}, {"s%=", AssignmentOperatorPrecedence},
	{"u%=", AssignmentOperatorPrecedence}, {"&=", AssignmentOperatorPrecedence}, {"|=", AssignmentOperatorPrecedence},
	{"^=", AssignmentOperatorPrecedence}, {">>=", AssignmentOperatorPrecedence}, {"s>>=", AssignmentOperatorPrecedence},
	{"u>>=", AssignmentOperatorPrecedence}, {"<<=", AssignmentOperatorPrecedence},
	{"s<<=", AssignmentOperatorPrecedence}, {"u<<=", AssignmentOperatorPrecedence}, {"?", TernaryOperatorPrecedence},
	{":", TernaryOperatorPrecedence}, {"||", LogicalOrOperatorPrecedence}, {"or", LogicalOrOperatorPrecedence},
	{"&&", LogicalAndOperatorPrecedence}, {"and", LogicalAndOperatorPrecedence}, {"&", BitwiseAndOperatorPrecedence},
	{"|", BitwiseOrOperatorPrecedence}, {"^", BitwiseXorOperatorPrecedence}, {"==", EqualityOperatorPrecedence},
	{"===", EqualityOperatorPrecedence}, {"!=", EqualityOperatorPrecedence}, {"!==", EqualityOperatorPrecedence},
	{"<>", EqualityOperatorPrecedence}, {"<", CompareOperatorPrecedence}, {"s<", CompareOperatorPrecedence},
	{"u<", CompareOperatorPrecedence}, {"<=", CompareOperatorPrecedence}, {"s<=", CompareOperatorPrecedence},
	{"u<=", CompareOperatorPrecedence}, {">", CompareOperatorPrecedence}, {"s>", CompareOperatorPrecedence},
	{"u>", CompareOperatorPrecedence}, {">=", CompareOperatorPrecedence}, {"s>=", CompareOperatorPrecedence},
	{"u>=", CompareOperatorPrecedence}, {"<<", ShiftOperatorPrecedence}, {"s<<", ShiftOperatorPrecedence},
	{"u<<", ShiftOperatorPrecedence}, {">>", ShiftOperatorPrecedence}, {"s>>", ShiftOperatorPrecedence},
	{"u>>", ShiftOperatorPrecedence}, {"+", AddOperatorPrecedence}, {"-", AddOperatorPrecedence},
	{"*", MultiplyOperatorPrecedence}, {"/", MultiplyOperatorPrecedence}, {"s/", MultiplyOperatorPrecedence},
	{"u/", MultiplyOperatorPrecedence}, {"%", MultiplyOperatorPrecedence}, {"s%", MultiplyOperatorPrecedence},
	{"u%", MultiplyOperatorPrecedence}, {"!", UnaryOperatorPrecedence}, {"not", UnaryOperatorPrecedence},
	{"~", UnaryOperatorPrecedence}};


static BNOperatorPrecedence GetOperatorPrecedence(const InstructionTextToken& token, size_t* ternary = nullptr)
{
	string trimmedText = TrimString(token.text);
	auto i = g_operatorPrecedenceMap.find(trimmedText);
	if (i != g_operatorPrecedenceMap.end())
	{
		if (i->second == TernaryOperatorPrecedence && ternary)
		{
			// HLIL uses ':' in additional contexts, so look for active ternary operators before
			// treating it as part of a ternary
			if (trimmedText == "?")
			{
				(*ternary)++;
			}
			else if (trimmedText == ":")
			{
				if (*ternary)
					(*ternary)--;
				else
					return MemberAndFunctionOperatorPrecedence;
			}
		}
		return i->second;
	}
	return MemberAndFunctionOperatorPrecedence;
}


struct Item
{
	ItemType type;
	vector<Item> items;
	vector<InstructionTextToken> tokens;
	size_t width;

	void AppendAllTokens(vector<InstructionTextToken>& output, bool& firstTokenOfLine)
	{
		if (firstTokenOfLine)
		{
			if (!tokens.empty())
			{
				InstructionTextToken token = tokens.front();
				string trimmedText = TrimLeadingWhitespace(token.text);
				token.width -= token.text.size() - trimmedText.size();
				token.text = trimmedText;
				output.push_back(token);
				output.insert(output.end(), tokens.begin() + 1, tokens.end());
				firstTokenOfLine = false;
			}
		}
		else
		{
			output.insert(output.end(), tokens.begin(), tokens.end());
		}

		for (auto& item : items)
			item.AppendAllTokens(output, firstTokenOfLine);
	}

	void AddTokenToLastAtom(const InstructionTextToken& token)
	{
		if (!tokens.empty())
			tokens.push_back(token);
		else if (items.empty())
			items.push_back(Item {Atom, {}, {token}, 0});
		else
			items.back().AddTokenToLastAtom(token);
	}

	void CalculateWidth()
	{
		width = 0;
		for (auto& token : tokens)
			width += token.width;
		for (auto& item : items)
		{
			item.CalculateWidth();
			width += item.width;
		}
	}
};


struct ItemLayoutStackEntry
{
	vector<Item> items;
	size_t additionalContinuationIndentation;
	size_t desiredWidth;
	size_t desiredContinuationWidth;
	bool newLineOnReenteringScope;
};


static vector<Item> CreateStatementItems(const vector<Item>& items)
{
	vector<Item> result, pending;
	bool hasArgs = false;
	for (auto& i : items)
	{
		if (i.type == StatementSeparator)
		{
			if (pending.empty())
			{
				result.push_back(Item {Atom, {}, {i.tokens}, 0});
			}
			else
			{
				for (auto& j : i.tokens)
					pending.back().AddTokenToLastAtom(j);
				result.push_back(Item {Statement, pending, {}, 0});
			}
			pending.clear();
			hasArgs = true;
		}
		else if (i.type == StartOfContainer && pending.empty())
		{
			result.push_back(i);
		}
		else if (i.type == EndOfContainer && hasArgs && !pending.empty())
		{
			result.push_back(Item {Statement, pending, {}, 0});
			result.push_back(i);
			pending.clear();
		}
		else
		{
			pending.push_back(Item {i.type, CreateStatementItems(i.items), i.tokens, 0});
		}
	}

	if (!pending.empty())
	{
		if (hasArgs)
			result.push_back(Item {Statement, pending, {}, 0});
		else
			result.insert(result.end(), pending.begin(), pending.end());
	}

	return result;
}


static vector<Item> CreateAssignmentOperatorGroups(const vector<Item>& items)
{
	vector<Item> result, pending;
	bool hasOperators = false;
	for (auto& i : items)
	{
		if (i.type == Operator && !i.tokens.empty())
		{
			BNOperatorPrecedence precedence = GetOperatorPrecedence(i.tokens[0]);
			if (precedence == AssignmentOperatorPrecedence)
			{
				if (pending.empty())
				{
					result.push_back(Item {Atom, {}, {i.tokens}, 0});
				}
				else
				{
					for (auto& j : i.tokens)
						pending.back().AddTokenToLastAtom(j);
					result.push_back(Item {Statement, pending, {}, 0});
				}
				pending.clear();
				hasOperators = true;
				continue;
			}
		}

		if (i.type == StartOfContainer && pending.empty())
		{
			result.push_back(i);
		}
		else if (i.type == EndOfContainer && hasOperators && !pending.empty())
		{
			result.push_back(Item {Group, pending, {}, 0});
			result.push_back(i);
			pending.clear();
		}
		else
		{
			pending.push_back(Item {i.type, CreateAssignmentOperatorGroups(i.items), i.tokens, 0});
		}
	}

	if (!pending.empty())
	{
		if (hasOperators)
			result.push_back(Item {Group, pending, {}, 0});
		else
			result.insert(result.end(), pending.begin(), pending.end());
	}

	return result;
}


static vector<Item> CreateArgumentItems(const vector<Item>& items, bool inContainer)
{
	vector<Item> result, pending;
	bool hasArgs = false;
	for (auto& i : items)
	{
		if (i.type == ArgumentSeparator)
		{
			if (pending.empty())
			{
				result.push_back(Item {Atom, {}, {i.tokens}, 0});
			}
			else
			{
				for (auto& j : i.tokens)
					pending.back().AddTokenToLastAtom(j);
				result.push_back(Item {inContainer ? Argument : Group, pending, {}, 0});
			}
			pending.clear();
			hasArgs = true;
		}
		else if (i.type == StartOfContainer && pending.empty())
		{
			result.push_back(i);
		}
		else if (i.type == EndOfContainer && hasArgs && !pending.empty())
		{
			result.push_back(Item {inContainer ? Argument : Group, pending, {}, 0});
			result.push_back(i);
			pending.clear();
		}
		else
		{
			pending.push_back(Item {i.type, CreateArgumentItems(i.items, i.type == Container), i.tokens, 0});
		}
	}

	if (!pending.empty())
	{
		if (hasArgs)
			result.push_back(Item {inContainer ? Argument : Group, pending, {}, 0});
		else
			result.insert(result.end(), pending.begin(), pending.end());
	}

	return result;
}


static vector<Item> CreateOperatorGroups(const vector<Item>& items)
{
	vector<Item> result, pending;
	bool hasOperators = false;
	for (auto& i : items)
	{
		if (i.type == Operator)
		{
			if (pending.size() == 1)
				result.push_back(pending[0]);
			else if (!pending.empty())
				result.push_back(Item {Group, pending, {}, 0});
			result.push_back(i);
			pending.clear();
			hasOperators = true;
			continue;
		}

		if (i.type == StartOfContainer && pending.empty())
		{
			result.push_back(i);
		}
		else if (i.type == EndOfContainer && hasOperators && pending.size() > 1)
		{
			result.push_back(Item {Group, pending, {}, 0});
			result.push_back(i);
			pending.clear();
		}
		else
		{
			pending.push_back(Item {i.type, CreateOperatorGroups(i.items), i.tokens, 0});
		}
	}

	if (!pending.empty())
	{
		if (hasOperators && pending.size() > 1)
			result.push_back(Item {Group, pending, {}, 0});
		else
			result.insert(result.end(), pending.begin(), pending.end());
	}

	return result;
}


static vector<Item> CreateOperatorPrecedenceGroups(const vector<Item>& items)
{
	// Look for the operator with the lowest precedence. These will be grouped first.
	optional<BNOperatorPrecedence> lowestPrecedence;
	size_t ternary = 0;
	for (auto i = items.begin(); i != items.end(); ++i)
	{
		if (i != items.begin() && i->type == Operator && !i->tokens.empty())
		{
			BNOperatorPrecedence precedence = GetOperatorPrecedence(i->tokens[0], &ternary);
			if (!lowestPrecedence.has_value() || precedence < lowestPrecedence.value())
				lowestPrecedence = precedence;
		}
	}

	// If there were no operators, no need to group at this level. Just traverse down into child items.
	if (!lowestPrecedence.has_value())
	{
		vector<Item> result;
		result.reserve(items.size());
		for (auto& i : items)
			result.push_back({i.type, CreateOperatorPrecedenceGroups(i.items), i.tokens, 0});
		return result;
	}

	// Go through the items and split the items into groups around the lowest precedence operator
	vector<Item> result, pending;
	ternary = 0;
	for (auto i = items.begin(); i != items.end(); ++i)
	{
		if (i != items.begin() && i->type == Operator && !i->tokens.empty())
		{
			BNOperatorPrecedence precedence = GetOperatorPrecedence(i->tokens[0], &ternary);
			if (precedence == lowestPrecedence.value())
			{
				if (pending.size() == 1)
					result.push_back(pending[0]);
				else if (!pending.empty())
					result.push_back(Item {Group, pending, {}, 0});
				else
					result.insert(result.end(), pending.begin(), pending.end());
				pending.clear();
			}
		}

		if (i->type == StartOfContainer && pending.empty())
		{
			result.push_back(*i);
		}
		else if (i->type == EndOfContainer && pending.size() > 1 && !result.empty())
		{
			result.push_back(Item {Group, pending, {}, 0});
			result.push_back(*i);
			pending.clear();
		}
		else
		{
			pending.push_back(*i);
		}
	}

	if (!pending.empty())
	{
		if (pending.size() > 1 && !result.empty())
			result.push_back(Item {Group, pending, {}, 0});
		else
			result.insert(result.end(), pending.begin(), pending.end());
	}

	// Recurse into these groups and process the next lowest precedence in each
	vector<Item> processed;
	processed.reserve(result.size());
	for (auto& i : result)
		processed.push_back({i.type, CreateOperatorPrecedenceGroups(i.items), i.tokens, 0});
	return processed;
}


static vector<Item> RelocateStartAndEndOfContainerItems(const vector<Item>& items)
{
	vector<Item> result;
	for (auto& i : items)
	{
		if (!result.empty() && i.type == Container && !i.items.empty() && i.items.front().type == StartOfContainer)
		{
			Item startOfContainer = i.items.front();
			for (auto& j : startOfContainer.tokens)
				result.back().AddTokenToLastAtom(j);

			vector<Item> containerItems(i.items.begin() + 1, i.items.end());
			containerItems = RelocateStartAndEndOfContainerItems(containerItems);
			result.push_back({Container, containerItems, {}, 0});
		}
		else if (i.type == EndOfContainer && !result.empty())
		{
			for (auto& j : i.tokens)
				result.back().AddTokenToLastAtom(j);
		}
		else
		{
			result.push_back(Item {i.type, RelocateStartAndEndOfContainerItems(i.items), i.tokens, 0});
		}
	}
	return result;
}


GenericLineFormatter::GenericLineFormatter(): LineFormatter("GenericLineFormatter")
{
}


vector<DisassemblyTextLine> GenericLineFormatter::FormatLines(
	const vector<DisassemblyTextLine>& lines, const LineFormatterSettings& settings)
{
	vector<DisassemblyTextLine> result;
	for (size_t i = 0; i < lines.size(); i++)
	{
		const DisassemblyTextLine& currentLine = lines[i];

		size_t totalLength = currentLine.GetTotalWidth();
		size_t indentation = currentLine.GetAddressAndIndentationWidth();

		// Check width against settings
		size_t contentLength = totalLength - indentation;
		if (totalLength <= settings.desiredLineLength || contentLength <= settings.minimumContentLength)
		{
			// Line fits, emit as-is
			result.push_back(currentLine);
			continue;
		}

		// Calculate indentation for continuation lines. If the next line in the input is more indented, make
		// the continuation lines more indented than that to separate the continuation from the new scope.
		size_t continuationIndentation = indentation + settings.tabWidth;
		if ((i + 1) < lines.size())
		{
			size_t nextLineIndentation = lines[i + 1].GetAddressAndIndentationWidth();
			if (nextLineIndentation > indentation)
				continuationIndentation = nextLineIndentation + settings.tabWidth;
		}
		size_t additionalContinuationIndentation = continuationIndentation - indentation;

		// Compute the target length for this line
		size_t desiredWidth = settings.minimumContentLength;
		if (indentation < settings.desiredLineLength)
		{
			size_t remainingWidth = settings.desiredLineLength - indentation;
			if (remainingWidth > desiredWidth)
				desiredWidth = remainingWidth;
		}

		// Compute the target length for the continuation lines
		size_t desiredContinuationWidth = settings.minimumContentLength;
		if (continuationIndentation < settings.desiredLineLength)
		{
			size_t remainingWidth = settings.desiredLineLength - continuationIndentation;
			if (remainingWidth > desiredContinuationWidth)
				desiredContinuationWidth = remainingWidth;
		}

		// Gather the indentation tokens at the beginning of the line
		vector<InstructionTextToken> indentationTokens = currentLine.GetAddressAndIndentationTokens();
		size_t tokenIndex = indentationTokens.size();

		// First break the line down into nested container items. A container is anything between a pair of
		// BraceTokens (except for strings, where the entire string, including the quotes, are treated as
		// a single atom).
		vector<Item> items;
		stack<vector<Item>> itemStack;
		for (; tokenIndex < currentLine.tokens.size(); tokenIndex++)
		{
			const InstructionTextToken& token = currentLine.tokens[tokenIndex];
			string trimmedText = TrimString(token.text);

			switch (token.type)
			{
			case BraceToken:
				if (tokenIndex + 1 < currentLine.tokens.size()
					&& currentLine.tokens[tokenIndex + 1].type == StringToken)
				{
					// Treat string tokens surrounded by brace tokens as a unit (this is usually the quotes
					// surrounding the string)
					Item atom;
					atom.type = Atom;
					atom.tokens.push_back(token);
					atom.tokens.push_back(currentLine.tokens[tokenIndex + 1]);
					atom.width = 0;
					tokenIndex++;
					if (tokenIndex + 1 < currentLine.tokens.size()
						&& currentLine.tokens[tokenIndex + 1].type == BraceToken)
					{
						atom.tokens.push_back(currentLine.tokens[tokenIndex + 1]);
						tokenIndex++;
					}

					items.push_back(atom);
					break;
				}

				if (trimmedText == "(" || trimmedText == "[" || trimmedText == "{")
				{
					// Create a ContainerContents item and place it onto the item stack. This will hold anything
					// inside the container once the end of the container is found.
					items.push_back(Item {Container, {}, {}, 0});
					itemStack.push(items);

					// Starting a new context
					items.clear();
					items.push_back(Item {StartOfContainer, {}, {token}, 0});
				}
				else if (trimmedText == ")" || trimmedText == "]" || trimmedText == "}")
				{
					items.push_back(Item {EndOfContainer, {}, {token}, 0});

					if (itemStack.empty())
						break;

					// Go back up the item stack and add the items to the container
					vector<Item> parent = itemStack.top();
					itemStack.pop();
					parent.back().items.insert(parent.back().items.end(), items.begin(), items.end());
					items = parent;
				}
				break;
			case CommentToken:
			{
				// The rest of the line is a comment. There may be tokens that are not of CommentToken type, but
				// these are used to create clickable items when things are referenced by the comment.
				Item comment {Comment, {}, {}, 0};
				for (; tokenIndex < currentLine.tokens.size(); tokenIndex++)
					comment.tokens.push_back(currentLine.tokens[tokenIndex]);
				items.push_back(comment);
				break;
			}
			case TextToken:
				if (trimmedText == ",")
					items.push_back(Item {ArgumentSeparator, {}, {token}, 0});
				else if ((!trimmedText.empty() && trimmedText[0] == '.') || trimmedText == "->")
					items.push_back(Item {FieldAccessor, {}, {token}, 0});
				else if (trimmedText == ";")
					items.push_back(Item {StatementSeparator, {}, {token}, 0});
				else if (trimmedText == ":" && !items.empty())
					items.back().AddTokenToLastAtom(token);
				else
					items.push_back(Item {Atom, {}, {token}, 0});
				break;
			case OperationToken:
				if ((!trimmedText.empty() && trimmedText[0] == '.') || trimmedText == "->")
					items.push_back(Item {FieldAccessor, {}, {token}, 0});
				else
					items.push_back(Item {Operator, {}, {token}, 0});
				break;
			default:
				items.push_back(Item {Atom, {}, {token}, 0});
				break;
			}
		}

		while (!itemStack.empty())
		{
			vector<Item> parent = itemStack.top();
			itemStack.pop();
			parent.back().items.insert(parent.back().items.end(), items.begin(), items.end());
			items = parent;
		}

		// Process the items to find semicolons, and create statement items containing the group of items making
		// up each statement.
		items = CreateStatementItems(items);

		// Process the items to find assignment operators, and group up the source and destination items. This needs
		// to be done before creating arguments to better handle multiple return value constructs.
		items = CreateAssignmentOperatorGroups(items);

		// Process the items to find commas, and create argument items containing the group of items making
		// up each argument.
		items = CreateArgumentItems(items, false);

		// Process the items to find operators, and create group items containing the operands
		items = CreateOperatorGroups(items);

		// Process the items to group operations by operator precedence
		items = CreateOperatorPrecedenceGroups(items);

		// Move start of container items to the last token of the previous item, and end of container items to
		// the previous atom.
		items = RelocateStartAndEndOfContainerItems(items);

		// Now that items are done, compute widths for layout
		for (auto& j : items)
			j.CalculateWidth();

		DisassemblyTextLine outputLine = currentLine;
		outputLine.tokens = indentationTokens;
		size_t currentWidth = 0;
		bool firstTokenOfLine = true;

		stack<ItemLayoutStackEntry> layoutStack;
		layoutStack.push({items, additionalContinuationIndentation, desiredWidth, desiredContinuationWidth, false});

		auto newLine = [&]() {
			if (!firstTokenOfLine)
			{
				string lastTokenText = outputLine.tokens.back().text;
				string trimmedText = TrimTrailingWhitespace(lastTokenText);
				outputLine.tokens.back().width -= lastTokenText.size() - trimmedText.size();
				outputLine.tokens.back().text = trimmedText;
			}

			result.push_back(outputLine);
			outputLine.tokens = indentationTokens;

			// Make sure any collapsible state indicators are set to padding so that the indicators don't
			// show up more than once for a single scope.
			for (auto& outToken : outputLine.tokens)
			{
				if (outToken.type == CollapseStateIndicatorToken)
					outToken.context = ContentCollapsiblePadding;
			}

			outputLine.tokens.emplace_back(TextToken, string(additionalContinuationIndentation, ' '));
			currentWidth = 0;
			desiredWidth = desiredContinuationWidth;
			firstTokenOfLine = true;
		};

		while (!layoutStack.empty())
		{
			ItemLayoutStackEntry layoutStackEntry = layoutStack.top();
			layoutStack.pop();

			items = layoutStackEntry.items;
			additionalContinuationIndentation = layoutStackEntry.additionalContinuationIndentation;
			desiredWidth = layoutStackEntry.desiredWidth;
			desiredContinuationWidth = layoutStackEntry.desiredContinuationWidth;

			// Check to see if the scope we are returning to needs a new line. This is used when an argument
			// spans multiple lines. The rest of the arguments are placed on separate lines from the long argument.
			if (layoutStackEntry.newLineOnReenteringScope && currentWidth > 0)
				newLine();

			for (auto item = items.begin(); item != items.end();)
			{
				if (currentWidth + item->width > desiredWidth)
				{
					// Current item is too wide to fit on the current line, will need to start a new line.
					auto next = item;
					++next;

					// If we are already on a fresh line, or the item is too wide to fit on a new line of its
					// own, we have to start emitting tokens and wrap in the middle of the item. If the item
					// is a container, always use the splitting behavior.
					if (currentWidth == 0 || item->width > desiredContinuationWidth || item->type == Container)
					{
						if (item->type == Argument && currentWidth != 0)
						{
							// If an argument is too wide to show on a single line all by itself, start the argument
							// on a new line, and add additional indentation for the continuation of the argument.
							if (next != items.end())
							{
								layoutStack.push({vector(next, items.end()), additionalContinuationIndentation,
									desiredWidth, desiredContinuationWidth, true});
							}

							newLine();

							additionalContinuationIndentation += settings.tabWidth;
							if (desiredContinuationWidth < settings.minimumContentLength + settings.tabWidth)
								desiredContinuationWidth = settings.minimumContentLength;
							else
								desiredContinuationWidth -= settings.tabWidth;

							layoutStack.push({item->items, additionalContinuationIndentation, desiredWidth,
								desiredContinuationWidth, false});
							break;
						}

						if (item->tokens.empty())
						{
							// Item contains other items. Place the context onto the layout stack and resume processing.
							if (next != items.end())
							{
								layoutStack.push({vector(next, items.end()), additionalContinuationIndentation,
									desiredWidth, desiredContinuationWidth, false});
							}
							layoutStack.push({item->items, additionalContinuationIndentation, desiredWidth,
								desiredContinuationWidth, false});
							break;
						}

						// Item is an atom. We just have to emit the tokens even though it is too wide.
						item->AppendAllTokens(outputLine.tokens, firstTokenOfLine);
						++item;
						continue;
					}

					// Start a new line and add the item on the fresh line.
					newLine();
					continue;
				}

				// Item fits, emit all tokens for it
				item->AppendAllTokens(outputLine.tokens, firstTokenOfLine);
				currentWidth += item->width;
				++item;
			}
		}

		// Emit the last line if it had tokens
		if (currentWidth > 0)
			newLine();
	}

	return result;
}


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifndef DEMO_EDITION
	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
	}
#endif

#ifdef DEMO_EDITION
	bool GenericFormatterPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		GenericLineFormatter* formatter = new GenericLineFormatter();
		LineFormatter::Register(formatter);
		return true;
	}
}
