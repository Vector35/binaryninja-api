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
	StringComponent,
	StringSeparator,
	StringWhitespace,
	FormatSpecifier,
	EscapeSequence,
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
				output.emplace_back(token);
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
			tokens.emplace_back(token);
		else if (items.empty())
			items.emplace_back(Item {Atom, {}, {token}, 0});
		else
			items.back().AddTokenToLastAtom(token);
	}

	void AddTokenToLastStringComponent(const InstructionTextToken& token)
	{
		if (!tokens.empty())
			tokens.emplace_back(token);
		else if (items.empty())
			items.emplace_back(Item {StringComponent, {}, {token}, 0});
		else
			items.back().AddTokenToLastStringComponent(token);
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
	size_t desiredStringWidth;
	bool newLineOnReenteringScope;
};

static vector<Item> CreateStatementItems(const vector<Item>& items)
{
    vector<Item> result;
    result.reserve(items.size());

    vector<Item> pending;
    pending.reserve(items.size());

    bool hasArgs = false;

    auto flushStatement = [&]() {
        if (!pending.empty()) {
            result.emplace_back(
                Item{
                    Statement,
                    std::move(pending),
                    vector<InstructionTextToken>{},
                    0
                }
            );
            pending.clear();
        }
    };

    for (auto const& orig : items) {
        // copy so we can move out of i.tokens / i.items safely
        Item i = orig;

        if (i.type == StatementSeparator) {
            hasArgs = true;

            if (pending.empty()) {
                // first separator in this statement
                result.emplace_back(
                    Item{
                        Atom,
                        {},
                        std::move(i.tokens),
                        0
                    }
                );
            } else {
                // append tokens to last atom in pending, then flush
                for (auto& t : i.tokens)
                    pending.back().AddTokenToLastAtom(std::move(t));
                flushStatement();
            }
        }
        else if (i.type == StartOfContainer && pending.empty()) {
            // emit container boundary directly if no pending args
            result.emplace_back(std::move(i));
        }
        else if (i.type == EndOfContainer && hasArgs && !pending.empty()) {
            // flush any accumulated args as a Statement, then emit the container end
            flushStatement();
            result.emplace_back(std::move(i));
        }
        else {
            // accumulate everything else for possible statement grouping
            vector<Item> nested;
            if (!i.items.empty())
                nested = CreateStatementItems(i.items);

            pending.emplace_back(
                Item{
                    i.type,
                    std::move(nested),
                    std::move(i.tokens),
                    0
                }
            );
        }
    }

    // final tail: either flush into a Statement or append raw
    if (!pending.empty()) {
        if (hasArgs) {
            flushStatement();
        } else {
            result.insert(
                result.end(),
                make_move_iterator(pending.begin()),
                make_move_iterator(pending.end())
            );
        }
    }

    return result;
}

static vector<InstructionTextToken> ParseStringToken(
    const InstructionTextToken& unprocessedStringToken,
    const size_t maxParsingLength
)
{
	const string_view src = unprocessedStringToken.text;
	const size_t tail = src.size();

	vector<InstructionTextToken> result;
	size_t curStart = 0, curEnd = 0;

	auto ConstructToken = [&](size_t start, size_t end)
	{
		InstructionTextToken token = unprocessedStringToken;
		token.text = string(src.substr(start, end - start));
		token.width = token.text.size();
		result.emplace_back(std::move(token));
	};

	auto flushToken = [&](size_t start, size_t end)
	{
		if (start < end)
			ConstructToken(start, end);
	};

	// We generally split along spaces while keeping words intact, but some cases have
	// specific splitting behavior:
	//
	// - Any format specifier (starting with %) will be treated as an atom even if embedded
	//   within a word
	// - Any escape sequence will also be treated as an atom
	// - We split along punctuation like commas, colons, periods, and semicolons, grouping
	//   trailing punctuation together.
    while (curEnd < tail)
    {
        char c = src[curEnd];

        if (c == '%')
        {
        	// Flush before format specifier
        	flushToken(curStart, curEnd);

            size_t start = curEnd;
            curEnd++;
            while (curEnd < tail && (isalnum(src[curEnd]) || src[curEnd]=='.' || src[curEnd]=='-'))
                curEnd++;
            ConstructToken(start, curEnd);
            curStart = curEnd;
        }
        else if (c == '\\')
        {
        	// Flush before escape sequence
			flushToken(curStart, curEnd);

            size_t start = curEnd;
            curEnd++;  // consume '\'
            if (curEnd < tail)
                curEnd++;  // consume escaped char
            ConstructToken(start, curEnd);
            curStart = curEnd;
        }
    	else if (isspace(c))
    	{
    		// Flush before whitespace
    		flushToken(curStart, curEnd);

    		size_t start = curEnd;
    		while (curEnd < tail && isspace(src[curEnd]))
    			curEnd++;
    		ConstructToken(start, curEnd);
    		curStart = curEnd;
    	}
        else if (c == ',' || c == '.' || c == ':' || c == ';')
        {
        	// Flush before punctuation
        	flushToken(curStart, curEnd);

			// Group together repeated punctuation
            size_t start = curEnd;
            while (curEnd < tail && src[curEnd] == c)
                curEnd++;
            ConstructToken(start, curEnd);
            curStart = curEnd;
        }
        else
        {
            curEnd++;
        }

        // Check if we've exceeded max parsing length
        if (curEnd > maxParsingLength)
        {
	        // Flush any pending token
	        flushToken(curStart, maxParsingLength);

	        // Create single token with remaining text
	        InstructionTextToken remainingToken = unprocessedStringToken;
	        remainingToken.text = string(src.substr(maxParsingLength));
	        remainingToken.width = remainingToken.text.size();
	        result.emplace_back(std::move(remainingToken));
	        return result;
        }
    }

	flushToken(curStart, curEnd);
    return result;
}

static vector<Item> CreateStringGroups(const vector<Item>& items)
{
    // We handle strings mostly the same as other types except the introduction
    // of the StringComponent and StringWhitespace types.
    //
    // The reason we introduce these is for the specific behaviors when formatting multiline
    // string annotations. String annotations have a different desired width than tokens
    // like arguments, comments, etc.
    //
    // Additionally, we don't wrap trailing whitespace until the preceding token is within
    // the wrapping width, unlike other token types.

	vector<Item> result;
    result.reserve(items.size());
    vector<Item> pending;
    pending.reserve(items.size());
    bool hasStrings = false;

    // flush pending into one StringComponent
    auto flushString = [&]() {
        if (!pending.empty()) {
            result.emplace_back(
                Item{ StringComponent,
                      std::move(pending),
                      {},
                      0 }
            );
            pending.clear();
        }
    };

    for (auto const& orig : items) {
        Item i = orig;

        if (i.type == StringSeparator && !i.tokens.empty()) {
            if (pending.empty()) {
                result.emplace_back(
                    Item{ StringComponent,
                          vector<Item>{},
                          std::move(i.tokens),
                          0 }
                );
            } else {
                for (auto& t : i.tokens)
                    pending.back().AddTokenToLastStringComponent(std::move(t));
                flushString();
            }
            hasStrings = true;
        }
        else if (i.type == StringWhitespace) {
            flushString();
            result.emplace_back(
                Item{ StringWhitespace,
                      std::move(i.items),
                      std::move(i.tokens),
                      0 }
            );
        }
        else if (i.type == FormatSpecifier || i.type == EscapeSequence) {
            flushString();
            result.emplace_back(
                Item{ StringComponent,
                      std::move(i.items),
                      std::move(i.tokens),
                      0 }
            );
        }
        else if (i.type == StartOfContainer && pending.empty()) {
            result.emplace_back(std::move(i));
        }
        else if (i.type == EndOfContainer && hasStrings && !pending.empty()) {
            result.emplace_back(
                Item{ Group,
                      std::move(pending),
                      vector<InstructionTextToken>{},
                      0 }
            );
            result.emplace_back(std::move(i));
            pending.clear();
        }
        else {
            vector<Item> nested;
            if (!i.items.empty())
                nested = CreateStringGroups(i.items);
            pending.emplace_back(
                Item{ i.type,
                      std::move(nested),
                      std::move(i.tokens),
                      0 }
            );
        }
    }

    if (!pending.empty()) {
        if (hasStrings) {
            flushString();
        } else {
            result.insert(
                result.end(),
                make_move_iterator(pending.begin()),
                make_move_iterator(pending.end())
            );
        }
    }

    return result;
}

static vector<Item> CreateAssignmentOperatorGroups(const vector<Item>& items)
{
	vector<Item> result;
	result.reserve(items.size());
	vector<Item> pending;
	pending.reserve(items.size());

	bool hasOperators = false;

	auto flushStatement = [&]()
	{
		if (!pending.empty())
		{
			result.emplace_back(Item {Statement, std::move(pending), {}, 0});
			pending.clear();
		}
	};

	for (auto& i : items)
	{
		if (i.type == Operator && !i.tokens.empty())
		{
			BNOperatorPrecedence precedence = GetOperatorPrecedence(i.tokens[0]);
			if (precedence == AssignmentOperatorPrecedence)
			{
				if (pending.empty())
				{
					result.emplace_back(Item {Atom, {}, std::move(i.tokens), 0});
				}
				else
				{
					for (auto& j : i.tokens)
						pending.back().AddTokenToLastAtom(j);
					flushStatement();
				}
				hasOperators = true;
				continue;
			}
		}

		if (i.type == StartOfContainer && pending.empty())
		{
			result.emplace_back(std::move(i));
		}
		else if (i.type == EndOfContainer && hasOperators && !pending.empty())
		{
			result.emplace_back(Item {Group, std::move(pending), {}, 0});
			result.emplace_back(i);
			pending.clear();
		}
		else
		{
			pending.emplace_back(Item {i.type, CreateAssignmentOperatorGroups(i.items), i.tokens, 0});
		}
	}

	if (!pending.empty())
	{
		if (hasOperators)
			result.emplace_back(Item {Group, std::move(pending), {}, 0});
		else
			result.insert(result.end(), pending.begin(), pending.end());
	}

	return result;
}


static vector<Item> CreateArgumentItems(const vector<Item>& items, bool inContainer)
{
	vector<Item> result;
	result.reserve(items.size());
	vector<Item> pending;
	pending.reserve(items.size());
	bool hasArgs = false;

	auto flushArgument = [&]()
	{
		if (!pending.empty())
		{
			result.emplace_back(
				Item{
					inContainer ? Argument : Group,
					std::move(pending),
					vector<InstructionTextToken>{},
					0
				}
			);
			pending.clear();
		}
	};

	for (auto const& orig: items)
	{
		Item i = orig;

		if (i.type == ArgumentSeparator)
		{
			if (pending.empty())
			{
				result.emplace_back(
					Item{
						Atom,
						vector<Item>{},
						std::move(i.tokens),
						0
					}
				);
			}
			else
			{
				for (auto& t: i.tokens)
					pending.back().AddTokenToLastAtom(std::move(t));
				flushArgument();
			}
			hasArgs = true;
		}
		else if (i.type == StartOfContainer && pending.empty())
		{
			result.emplace_back(std::move(i));
		}
		else if (i.type == EndOfContainer && hasArgs && !pending.empty())
		{
			flushArgument();
			result.emplace_back(std::move(i));
		}
		else
		{
			vector<Item> nested;
			if (!i.items.empty())
				nested = CreateArgumentItems(i.items, i.type == Container);
			pending.emplace_back(
				Item{
					i.type,
					std::move(nested),
					std::move(i.tokens),
					0
				}
			);
		}
	}

	if (!pending.empty())
	{
		if (hasArgs)
		{
			flushArgument();
		}
		else
		{
			result.insert(
				result.end(),
				make_move_iterator(pending.begin()),
				make_move_iterator(pending.end())
			);
		}
	}

	return result;
}


static vector<Item> CreateOperatorGroups(const vector<Item>& items)
{
	vector<Item> result;
	result.reserve(items.size());
	vector<Item> pending;
	pending.reserve(items.size());
	bool hasOperators = false;

	auto flushOperator = [&]()
	{
		if (!pending.empty())
		{
			if (pending.size() == 1)
			{
				result.emplace_back(std::move(pending[0]));
			}
			else
			{
				result.emplace_back(
					Item{
						Group,
						std::move(pending),
						{},
						0
					}
				);
			}
			pending.clear();
		}
	};

	for (auto const& orig: items)
	{
		Item i = orig;

		if (i.type == Operator)
		{
			flushOperator();
			result.emplace_back(std::move(i));
			hasOperators = true;
		}
		else if (i.type == StartOfContainer && pending.empty())
		{
			result.emplace_back(std::move(i));
		}
		else if (i.type == EndOfContainer && hasOperators && pending.size() > 1)
		{
			flushOperator();
			result.emplace_back(std::move(i));
		}
		else
		{
			vector<Item> nested;
			if (!i.items.empty())
				nested = CreateOperatorGroups(i.items);
			pending.emplace_back(
				Item{
					i.type,
					std::move(nested),
					std::move(i.tokens),
					0
				}
			);
		}
	}

	if (!pending.empty())
	{
		if (hasOperators && pending.size() > 1)
		{
			flushOperator();
		}
		else
		{
			result.insert(
				result.end(),
				make_move_iterator(pending.begin()),
				make_move_iterator(pending.end())
			);
		}
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
			result.emplace_back(Item {i.type, CreateOperatorPrecedenceGroups(i.items), i.tokens, 0});
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
					result.emplace_back(pending[0]);
				else if (!pending.empty())
					result.emplace_back(Item {Group, std::move(pending), {}, 0});
				else
					result.insert(result.end(), pending.begin(), pending.end());
				pending.clear();
			}
		}

		if (i->type == StartOfContainer && pending.empty())
		{
			result.emplace_back(*i);
		}
		else if (i->type == EndOfContainer && pending.size() > 1 && !result.empty())
		{
			result.emplace_back(Item {Group, std::move(pending), {}, 0});
			result.emplace_back(*i);
			pending.clear();
		}
		else
		{
			pending.emplace_back(*i);
		}
	}

	if (!pending.empty())
	{
		if (pending.size() > 1 && !result.empty())
			result.emplace_back(Item {Group, pending, {}, 0});
		else
			result.insert(result.end(), pending.begin(), pending.end());
	}

	// Recurse into these groups and process the next lowest precedence in each
	vector<Item> processed;
	processed.reserve(result.size());
	for (auto& i : result)
		processed.emplace_back(Item{i.type, CreateOperatorPrecedenceGroups(i.items), i.tokens, 0});
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

			auto containerContents = i.items.begin() + 1;
			if (containerContents != i.items.end() && containerContents->type == EndOfContainer)
			{
				for (auto& j : containerContents->tokens)
					result.back().AddTokenToLastAtom(j);
				++containerContents;
			}

			vector<Item> containerItems(containerContents, i.items.end());
			containerItems = RelocateStartAndEndOfContainerItems(containerItems);
			if (!containerItems.empty())
				result.emplace_back(Item {Container, containerItems, {}, 0});
		}
		else if (i.type == EndOfContainer && !result.empty())
		{
			for (auto& j : i.tokens)
				result.back().AddTokenToLastAtom(j);
		}
		else
		{
			result.emplace_back(Item {i.type, RelocateStartAndEndOfContainerItems(i.items), i.tokens, 0});
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
			result.emplace_back(currentLine);
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

		// Compute target string width for this line
		size_t desiredStringWidth = settings.stringWrappingWidth;
		if (indentation < settings.desiredLineLength)
		{
			size_t remainingStringWidth = settings.desiredLineLength - indentation;
			if (remainingStringWidth > desiredStringWidth)
				desiredStringWidth = remainingStringWidth;
		}

		// Gather the indentation tokens at the beginning of the line
		vector<InstructionTextToken> indentationTokens = currentLine.GetAddressAndIndentationTokens();
		size_t tokenIndex = indentationTokens.size();

		// First break the line down into nested container items. A container is anything between a pair of
		// BraceTokens
		vector<Item> items;
		stack<vector<Item>> itemStack;
		for (; tokenIndex < currentLine.tokens.size(); tokenIndex++)
		{
			const InstructionTextToken& token = currentLine.tokens[tokenIndex];
			string trimmedText = TrimString(token.text);

			switch (token.type)
			{
			case BraceToken:
				// Beginning of string
				if (trimmedText == "\"" && tokenIndex + 1 < currentLine.tokens.size()  && currentLine.tokens[tokenIndex + 1].type == StringToken)
				{
					// Create a ContainerContents item and place it onto the item stack. This will hold anything
					// inside the container once the end of the container is found.
					items.emplace_back(Item {Container, {}, {}, 0});
					itemStack.push(items);

					// Starting a new context
					items.clear();
					items.emplace_back(Item {StartOfContainer, {}, {token}, 0});
				}
				// End of string
				else if (trimmedText == "\"" && tokenIndex > 0 && currentLine.tokens[tokenIndex - 1].type == StringToken)
				{
					items.emplace_back(Item {EndOfContainer, {}, {token}, 0});

					if (itemStack.empty())
						break;

					// Go back up the item stack and add the items to the container
					vector<Item> parent = itemStack.top();
					itemStack.pop();
					parent.back().items.insert(parent.back().items.end(), items.begin(), items.end());
					items = parent;
				}
				else if (trimmedText == "(" || trimmedText == "[" || trimmedText == "{")
				{
					// Create a ContainerContents item and place it onto the item stack. This will hold anything
					// inside the container once the end of the container is found.
					items.emplace_back(Item {Container, {}, {}, 0});
					itemStack.push(items);

					// Starting a new context
					items.clear();
					items.emplace_back(Item {StartOfContainer, {}, {token}, 0});
				}
				else if (trimmedText == ")" || trimmedText == "]" || trimmedText == "}")
				{
					items.emplace_back(Item {EndOfContainer, {}, {token}, 0});

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
					comment.tokens.emplace_back(currentLine.tokens[tokenIndex]);
				items.emplace_back(comment);
				break;
			}
			case TextToken:
				if (trimmedText == ",")
					items.emplace_back(Item {ArgumentSeparator, {}, {token}, 0});
				else if ((!trimmedText.empty() && trimmedText[0] == '.') || trimmedText == "->")
					items.emplace_back(Item {FieldAccessor, {}, {token}, 0});
				else if (trimmedText == ";")
					items.emplace_back(Item {StatementSeparator, {}, {token}, 0});
				else if (trimmedText == ":" && !items.empty())
					items.back().AddTokenToLastAtom(token);
				else
					items.emplace_back(Item {Atom, {}, {token}, 0});
				break;
			case OperationToken:
				if ((!trimmedText.empty() && trimmedText[0] == '.') || trimmedText == "->")
					items.emplace_back(Item {FieldAccessor, {}, {token}, 0});
				else
					items.emplace_back(Item {Operator, {}, {token}, 0});
				break;
			case StringToken:
			{
				if (token.width > desiredWidth)
				{
					vector<InstructionTextToken> stringTokens = ParseStringToken(token, settings.maximumAnnotationLength);
					for (auto subToken : stringTokens)
					{
						string trimmedSubText = TrimString(subToken.text);
						if (trimmedSubText.empty())
							items.emplace_back(Item {StringWhitespace, {}, {subToken}, 0});
						else if (trimmedSubText[0] == '%')
							items.emplace_back(Item {FormatSpecifier, {}, {subToken}, 0});
						else if (!trimmedSubText.empty() && trimmedSubText[0] == '\\')
							items.emplace_back(Item {EscapeSequence, {}, {subToken}, 0});
						else if (trimmedSubText[0] == ',' || trimmedSubText[0] == '.' || trimmedSubText[0] == ':' || trimmedSubText[0] == ';')
							items.emplace_back(Item {StringSeparator, {}, {subToken}, 0});
						else
							items.emplace_back(Item {Atom, {}, {subToken}, 0});
					}
					break;
				}
				items.emplace_back(Item {Atom, {}, {token}, 0});
				break;
			}
			default:
				items.emplace_back(Item {Atom, {}, {token}, 0});
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

		// Create internal groupings for displaying strings -- grouping items by punctuation, format specifiers, and
		// escape sequences
		items = CreateStringGroups(items);

		// Now that items are done, compute widths for layout
		for (auto& j : items)
			j.CalculateWidth();

		DisassemblyTextLine outputLine = currentLine;
		outputLine.tokens = indentationTokens;
		size_t currentWidth = 0;
		bool firstTokenOfLine = true;

		stack<ItemLayoutStackEntry> layoutStack;
		layoutStack.push({items, additionalContinuationIndentation, desiredWidth, desiredContinuationWidth, desiredStringWidth, false});

		auto newLine = [&](const bool forString = false) {
			if (!firstTokenOfLine)
			{
				string lastTokenText = outputLine.tokens.back().text;
				string trimmedText = TrimTrailingWhitespace(lastTokenText);
				outputLine.tokens.back().width -= lastTokenText.size() - trimmedText.size();
				outputLine.tokens.back().text = trimmedText;
				if (forString && outputLine.tokens.back().type == StringToken)
				{
					outputLine.tokens.emplace_back(BraceToken, "\"");
					outputLine.tokens.back().width = 1;
					currentWidth += 1;
				}
			}

			result.emplace_back(outputLine);
			outputLine.tokens = indentationTokens;

			// Make sure any collapsible state indicators are set to padding so that the indicators don't
			// show up more than once for a single scope.
			for (auto& outToken : outputLine.tokens)
			{
				if (outToken.type == CollapseStateIndicatorToken)
					outToken.context = ContentCollapsiblePadding;
			}

			if (forString)
			{
				outputLine.tokens.emplace_back(BraceToken, "\"");
				currentWidth = 1;
				desiredWidth = desiredContinuationWidth;
				firstTokenOfLine = true;
				return;
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
			desiredStringWidth = layoutStackEntry.desiredStringWidth;

			// Check to see if the scope we are returning to needs a new line. This is used when an argument
			// spans multiple lines. The rest of the arguments are placed on separate lines from the long argument.
			if (layoutStackEntry.newLineOnReenteringScope && currentWidth > 0)
				newLine();

			for (auto item = items.begin(); item != items.end();)
			{
				if (currentWidth + item->width > desiredStringWidth && item->type == StringComponent)
				{
					auto next = item;
					++next;
					if (currentWidth > 0)
					{
						if (next != items.end())
						{
							layoutStack.push({vector(next, items.end()), additionalContinuationIndentation,
								desiredWidth, desiredContinuationWidth, desiredStringWidth, false});
						}

						newLine(true);
						if (desiredContinuationWidth < settings.minimumContentLength)
							desiredContinuationWidth = settings.minimumContentLength;

						layoutStack.push({item->items, additionalContinuationIndentation, desiredWidth,
							desiredContinuationWidth, desiredStringWidth, false});
						break;
					}

					item->AppendAllTokens(outputLine.tokens, firstTokenOfLine);
					currentWidth += item->width;
					++item;
					continue;
				}
				if (currentWidth + item->width > desiredWidth && item->type != StringWhitespace && item->type != StringComponent)
				{
					// Current item is too wide to fit on the current line, will need to start a new line.
					// Whitespace is allowed to be too wide; we push it on as the preceding word is wrapped.
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
									desiredWidth, desiredContinuationWidth, desiredStringWidth, true});
							}

							newLine();

							additionalContinuationIndentation += settings.tabWidth;
							if (desiredContinuationWidth < settings.minimumContentLength + settings.tabWidth)
								desiredContinuationWidth = settings.minimumContentLength;
							else
								desiredContinuationWidth -= settings.tabWidth;

							layoutStack.push({item->items, additionalContinuationIndentation, desiredWidth,
								desiredContinuationWidth, desiredStringWidth, false});
							break;
						}

						if (item->tokens.empty())
						{
							// Item contains other items. Place the context onto the layout stack and resume processing.
							if (next != items.end())
							{
								layoutStack.push({vector(next, items.end()), additionalContinuationIndentation,
									desiredWidth, desiredContinuationWidth, desiredStringWidth, false});
							}
							layoutStack.push({item->items, additionalContinuationIndentation, desiredWidth,
								desiredContinuationWidth, desiredStringWidth,  false});
							break;
						}

						// Item is an atom. We just have to emit the tokens even though it is too wide.
						item->AppendAllTokens(outputLine.tokens, firstTokenOfLine);
						currentWidth += item->width;
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
