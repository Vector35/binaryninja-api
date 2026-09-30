// Copyright (c) 2026 Vector 35 Inc
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

#pragma once

#include "base/expected.h"
#include "binaryninjaapi.h"
#include "rapidjsonwrapper.h"

#include <fmt/format.h>

#include <algorithm>
#include <concepts>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace BinaryNinja::MCP {

enum class Scope : uint8_t
{
	Global = GlobalScope,
	BinaryView = BinaryViewScope,
};

struct ToolDefinition
{
	std::string name;
	std::string title;
	std::string description;
	Scope scope = Scope::BinaryView;
	/*! BNMcpToolAnnotation flags. */
	uint32_t annotations = 0;
	/*! Empty for no output schema. */
	std::string outputSchema;
};

/*! A converted argument, or the message explaining why the argument is invalid. */
template <class T>
using ArgumentResult = bn::base::expected<T, std::string>;

/*! One invocation of a tool, as seen by the tool. The call's binary view and cancellation state
	are only available while the tool is running.
*/
class ToolCall: public CoreRefCountObject<BNMcpToolCall, BNNewMcpToolCallReference, BNFreeMcpToolCall>
{
public:
	explicit ToolCall(BNMcpToolCall* call);

	/*! Never null while a BinaryView-scoped tool is running. */
	Ref<BinaryNinja::BinaryView> GetBinaryView() const;
	bool IsCancelled() const;
	void ReportProgress(double progress, double total, const std::string& message = "") const;

	/*! An address is an expression string. An integer is an unsigned integer or an expression
		string. Expressions are evaluated against the call's binary view, with \c here as the value
		of the current address.
	*/
	ArgumentResult<uint64_t> ParseAddress(const rapidjson::Value& value, uint64_t here = 0) const;
	ArgumentResult<uint64_t> ParseInteger(const rapidjson::Value& value, uint64_t here = 0) const;
};

class ToolResult
{
	struct ErrorInfo
	{
		std::string code;
		std::string message;
		std::optional<std::string> details;
	};

	std::vector<std::string> m_text;
	std::optional<std::string> m_structuredContent;
	std::optional<ErrorInfo> m_error;
	std::vector<std::pair<std::string, std::string>> m_warnings;

public:
	/*! An empty, successful result. */
	ToolResult() = default;

	static ToolResult Text(std::string text);
	/*! When no text is added, clients that ignore structured content see it serialized as text. */
	static ToolResult Structured(const rapidjson::Value& content);
	static ToolResult Error(std::string code, std::string message, const rapidjson::Value* details = nullptr);

	ToolResult& AddText(std::string text);
	/*! An advisory warning about the result, such as analysis that has not finished. Clients see it
		in the structured content's reserved \c warnings member, and after any text.
	*/
	ToolResult& AddWarning(std::string code, std::string message);
	void ApplyTo(BNMcpToolResult* result) const;
	/*! Serialized as an MCP CallToolResult. */
	std::string ToJson() const;
};

class Tool: public CoreRefCountObject<BNMcpTool, BNNewMcpToolReference, BNFreeMcpTool>
{
public:
	explicit Tool(BNMcpTool* tool);

	/*! Sorted by name. */
	static std::vector<Ref<Tool>> GetList();
	static Ref<Tool> GetByName(const std::string& name);

	std::string GetName() const;
	std::string GetTitle() const;
	std::string GetDescription() const;
	std::string GetInputSchema() const;
	/*! Empty when the tool has no output schema. */
	std::string GetOutputSchema() const;
	Scope GetScope() const;
	uint32_t GetAnnotations() const;
};

using ToolHandler = std::function<ToolResult(ToolCall& call, const rapidjson::Value& arguments)>;

/*! A complete tool that has not been registered or created, as ToolBuilder::Build returns it. */
struct ToolSpec
{
	ToolDefinition definition;
	/*! A JSON Schema object with \c "type": \c "object". */
	std::string inputSchema;
	ToolHandler handler;
};

/*! Registers a tool for the life of the process. Returns null when the definition is invalid or
	its name is already registered. \c inputSchema is a JSON Schema object with \c "type": \c "object".
	A handler that throws produces an \c internal_error result.
*/
Ref<Tool> RegisterTool(const ToolDefinition& definition, const std::string& inputSchema, ToolHandler handler);


/*! The unsigned integer arguments converted so far in a call, in declaration order, for parameters
	evaluated relative to an earlier one.
*/
class ConvertedArguments
{
	std::vector<std::pair<std::string, uint64_t>> m_values;

public:
	void Set(std::string_view name, uint64_t value) { m_values.emplace_back(name, value); }

	std::optional<uint64_t> Get(std::string_view name) const
	{
		auto found = std::ranges::find(m_values, name, &std::pair<std::string, uint64_t>::first);
		if (found == m_values.end())
			return std::nullopt;
		return found->second;
	}
};

namespace detail {

using Allocator = rapidjson::Document::AllocatorType;

void AddProperty(rapidjson::Value& properties, std::string_view name, rapidjson::Value& schema, Allocator& allocator);
rapidjson::Value TypeSchema(const char* type, Allocator& allocator);
// Call after the type and constraints so that a schema reads as its type, its constraints, then its description.
void AddDescription(rapidjson::Value& schema, std::string_view description, Allocator& allocator);
std::string MissingMessage(std::string_view kind, std::string_view name);
std::string SerializeJson(const rapidjson::Value& value);

// Whether an argument can be the current address of a later IntegerExpression.
template <class T>
constexpr bool IsIntegerValued = std::is_same_v<T, uint64_t> || std::is_same_v<T, int64_t>
	|| std::is_same_v<T, std::optional<uint64_t>> || std::is_same_v<T, std::optional<int64_t>>;

// A negative value wraps, as it does in an expression.
template <class T>
std::optional<uint64_t> CurrentAddressValue(const T& value)
{
	if constexpr (std::is_same_v<T, uint64_t> || std::is_same_v<T, int64_t>)
		return static_cast<uint64_t>(value);
	else if constexpr (IsIntegerValued<T>)
		return value ? CurrentAddressValue(*value) : std::nullopt;
	else
		return std::nullopt;
}
// The message for the first argument that is not one of names.
std::optional<std::string> FindUnexpectedArgument(
	const rapidjson::Value& arguments, const std::vector<std::string>& names);
void LogRejectedTool(std::string_view name, std::string_view reason);

class InputSchemaBuilder
{
	std::string m_tool;
	rapidjson::Document m_schema;
	rapidjson::Value m_properties;
	rapidjson::Value m_required;
	std::vector<std::string> m_names;
	std::vector<std::string> m_integerNames;

public:
	explicit InputSchemaBuilder(std::string tool);

	// Throws std::invalid_argument for a duplicate name, or for a relativeTo that does not name an earlier integer
	// parameter.
	void Add(const std::string& name, bool required, const std::string* relativeTo, bool integer);
	rapidjson::Value& Properties() { return m_properties; }
	Allocator& GetAllocator() { return m_schema.GetAllocator(); }

	const std::vector<std::string>& GetNames() const { return m_names; }

	// Call once, after every parameter is declared.
	std::string Build();
};

// Reads a call's arguments. Read them in declaration order, since a RelativeTo parameter uses an earlier value.
class ArgumentReader
{
	ToolCall& m_call;
	const rapidjson::Value& m_arguments;
	ConvertedArguments m_converted;

public:
	ArgumentReader(ToolCall& call, const rapidjson::Value& arguments): m_call(call), m_arguments(arguments) {}

	ToolCall& GetCall() const { return m_call; }

	template <class P>
	ArgumentResult<typename P::Value> Read(const P& param)
	{
		// Clients may send null for an optional argument they leave unset.
		auto member = m_arguments.FindMember(param.GetName().c_str());
		bool absent = member == m_arguments.MemberEnd() || (!param.IsRequired() && member->value.IsNull());
		ArgumentResult<typename P::Value> result =
			absent ? param.Absent() : param.Convert(m_call, member->value, m_converted);
		if (!result)
			return result;

		if (std::optional<uint64_t> here = CurrentAddressValue(*result))
			m_converted.Set(param.GetName(), *here);
		return result;
	}
};

// Implements Declare, ParseArguments and Finish for a parameter kind that reads a single argument.
template <class Derived>
class SingleProperty
{
	const Derived& AsDerived() const { return static_cast<const Derived&>(*this); }

public:
	void Declare(InputSchemaBuilder& schema) const
	{
		const Derived& param = AsDerived();
		schema.Add(
			param.GetName(), param.IsRequired(), param.GetRelativeTo(), IsIntegerValued<typename Derived::Value>);
		param.AddSchema(schema.Properties(), schema.GetAllocator());
	}

	auto ParseArguments(ArgumentReader& reader) const { return reader.Read(AsDerived()); }

	template <class Parsed>
	bn::base::expected<Parsed, ToolResult> Finish(ToolCall&, Parsed& parsed) const
	{
		return std::move(parsed);
	}
};

// Parses each parameter's arguments in declaration order. Stops at the first invalid argument.
template <class... Params>
ArgumentResult<std::tuple<typename Params::Parsed...>> ParseArguments(
	const std::tuple<Params...>& params, ArgumentReader& reader)
{
	using Parsed = std::tuple<typename Params::Parsed...>;

	std::tuple<std::optional<typename Params::Parsed>...> parsed;
	std::optional<std::string> error;
	auto parse = [&](auto& slot, const auto& param) {
		if (error)
			return;

		auto result = param.ParseArguments(reader);
		if (result)
			slot.emplace(std::move(*result));
		else
			error = std::move(result.error());
	};
	return [&]<size_t... Index>(std::index_sequence<Index...>) -> ArgumentResult<Parsed> {
		(parse(std::get<Index>(parsed), std::get<Index>(params)), ...);
		if (error)
			return bn::base::unexpected(std::move(*error));

		return Parsed {std::move(*std::get<Index>(parsed))...};
	}(std::index_sequence_for<Params...> {});
}

template <class Result, class Error>
concept ExpectedWithError = std::same_as<Result, bn::base::expected<typename Result::value_type, Error>>;

template <class Fn, class... Args>
concept ParseFunction = requires(const Fn& parse, ToolCall& call, Args&... arguments) {
	{ parse(call, arguments...) } -> ExpectedWithError<std::string>;
};

template <class Fn, class... Args>
concept LookupFunction = requires(const Fn& lookup, ToolCall& call, Args&... arguments) {
	{ lookup(call, arguments...) } -> ExpectedWithError<ToolResult>;
};

// Used as a group's parse function when it has none. Returns the arguments unchanged, as a tuple.
struct KeepArguments
{
	template <class... Values>
	ArgumentResult<std::tuple<Values...>> operator()(ToolCall&, Values&... values) const
	{
		return std::tuple<Values...> {std::move(values)...};
	}
};

// Used as a group's lookup function when it has none. Returns the parsed value unchanged.
struct KeepParsed
{
	template <class Parsed>
	bn::base::expected<Parsed, ToolResult> operator()(ToolCall&, Parsed& parsed) const
	{
		return std::move(parsed);
	}
};

}  // namespace detail

/*! Parameters for MakeTool. Each parameter kind declares the JSON Schema it advertises and how its
	argument is checked and converted before the handler runs. \c Value is the type the handler
	receives. A parameter is required unless it is made optional or given a default.

	A kind provides \c Schema, \c Convert and \c MissingMessage, and a \c DefaultJson to support
	\c Default. \c Convert turns one argument into a value, and its error is reported as
	\c invalid_params. \c converted holds the values of earlier integer arguments, which
	IntegerExpression::RelativeTo uses.
*/
template <class Derived, class ValueType>
class Param: public detail::SingleProperty<Derived>
{
protected:
	std::string m_name;
	std::string m_description;

	const Derived& Self() const { return static_cast<const Derived&>(*this); }

public:
	using Value = ValueType;
	using Parsed = ValueType;

	Param(std::string name, std::string description): m_name(std::move(name)), m_description(std::move(description)) {}

	const std::string& GetName() const { return m_name; }
	bool IsRequired() const { return true; }
	/*! The earlier parameter this one is evaluated relative to, if any. */
	const std::string* GetRelativeTo() const { return nullptr; }

	void AddSchema(rapidjson::Value& properties, detail::Allocator& allocator) const
	{
		rapidjson::Value schema = Self().Schema(allocator);
		detail::AddProperty(properties, m_name, schema, allocator);
	}

	ArgumentResult<Value> Absent() const { return bn::base::unexpected(Self().MissingMessage()); }
};

/*! The handler receives <tt>std::optional<Value></tt>, empty when the argument is absent or null. */
template <class Kind>
class OptionalParam: public detail::SingleProperty<OptionalParam<Kind>>
{
	Kind m_param;

public:
	using Value = std::optional<typename Kind::Value>;
	using Parsed = Value;

	explicit OptionalParam(Kind param): m_param(std::move(param)) {}

	const std::string& GetName() const { return m_param.GetName(); }
	bool IsRequired() const { return false; }
	const std::string* GetRelativeTo() const { return m_param.GetRelativeTo(); }

	void AddSchema(rapidjson::Value& properties, detail::Allocator& allocator) const
	{
		m_param.AddSchema(properties, allocator);
	}

	ArgumentResult<Value> Absent() const { return Value {}; }

	ArgumentResult<Value> Convert(
		ToolCall& call, const rapidjson::Value& value, const ConvertedArguments& converted) const
	{
		auto result = m_param.Convert(call, value, converted);
		if (!result)
			return bn::base::unexpected(std::move(result.error()));

		return Value {std::move(*result)};
	}
};

/*! The handler receives the default when the argument is absent or null. The schema advertises the
	default.
*/
template <class Kind>
class DefaultParam: public detail::SingleProperty<DefaultParam<Kind>>
{
	Kind m_param;
	typename Kind::Value m_default;

public:
	using Value = typename Kind::Value;
	using Parsed = Value;

	DefaultParam(Kind param, Value defaultValue): m_param(std::move(param)), m_default(std::move(defaultValue)) {}

	const std::string& GetName() const { return m_param.GetName(); }
	bool IsRequired() const { return false; }
	const std::string* GetRelativeTo() const { return m_param.GetRelativeTo(); }

	void AddSchema(rapidjson::Value& properties, detail::Allocator& allocator) const
	{
		rapidjson::Value schema = m_param.Schema(allocator);
		rapidjson::Value defaultValue = m_param.DefaultJson(m_default, allocator);
		schema.AddMember("default", defaultValue, allocator);
		detail::AddProperty(properties, m_param.GetName(), schema, allocator);
	}

	ArgumentResult<Value> Absent() const { return m_default; }
	ArgumentResult<Value> Convert(
		ToolCall& call, const rapidjson::Value& value, const ConvertedArguments& converted) const
	{
		return m_param.Convert(call, value, converted);
	}
};

/*! A parameter kind that can be made optional or given a default. */
template <class Derived, class ValueType>
class ValueParam: public Param<Derived, ValueType>
{
public:
	using Param<Derived, ValueType>::Param;

	OptionalParam<Derived> Optional() const { return OptionalParam<Derived>(this->Self()); }
	DefaultParam<Derived> Default(ValueType value) const { return DefaultParam<Derived>(this->Self(), std::move(value)); }
};

/*! A parameter kind that can describe and convert any one JSON value, such as String or UInt, so it
	can also describe and convert each item of a List.
*/
template <class Kind>
concept ParamKind = requires(const Kind& kind, ToolCall& call, const rapidjson::Value& value,
	const ConvertedArguments& converted, detail::Allocator& allocator) {
	typename Kind::Value;
	{ kind.Schema(allocator) } -> std::same_as<rapidjson::Value>;
	{ kind.MissingMessage() } -> std::same_as<std::string>;
	{ kind.GetRelativeTo() } -> std::same_as<const std::string*>;
	{ kind.Convert(call, value, converted) } -> std::same_as<ArgumentResult<typename Kind::Value>>;
};

/*! A parameter for ToolBuilder::Param, or an item kind for List, that accepts a JSON string. */
class String: public ValueParam<String, std::string>
{
	bool m_nonEmpty = false;

public:
	using ValueParam::ValueParam;

	/*! Rejects an empty string. */
	String& NonEmpty();

	rapidjson::Value Schema(detail::Allocator& allocator) const;
	rapidjson::Value DefaultJson(std::string_view value, detail::Allocator& allocator) const;
	std::string MissingMessage() const;
	ArgumentResult<std::string> Convert(
		ToolCall& call, const rapidjson::Value& value, const ConvertedArguments& converted) const;
};

/*! A parameter for ToolBuilder::Param, or an item kind for List, that accepts one of a fixed set
	of strings.
*/
class Choice: public ValueParam<Choice, std::string>
{
	std::vector<std::string> m_choices;

public:
	Choice(std::string name, std::string description, std::vector<std::string> choices);

	rapidjson::Value Schema(detail::Allocator& allocator) const;
	rapidjson::Value DefaultJson(std::string_view value, detail::Allocator& allocator) const;
	std::string MissingMessage() const;
	ArgumentResult<std::string> Convert(
		ToolCall& call, const rapidjson::Value& value, const ConvertedArguments& converted) const;
};

/*! A parameter for ToolBuilder::Param, or an item kind for List, that accepts a JSON boolean. */
class Bool: public ValueParam<Bool, bool>
{
public:
	using ValueParam::ValueParam;

	rapidjson::Value Schema(detail::Allocator& allocator) const;
	rapidjson::Value DefaultJson(bool value, detail::Allocator& allocator) const;
	std::string MissingMessage() const;
	ArgumentResult<bool> Convert(
		ToolCall& call, const rapidjson::Value& value, const ConvertedArguments& converted) const;
};

/*! A parameter for ToolBuilder::Param, or an item kind for List, that accepts a JSON unsigned
	integer.
*/
class UInt: public ValueParam<UInt, uint64_t>
{
	std::optional<uint64_t> m_maximum;
	bool m_clamp = false;

public:
	using ValueParam::ValueParam;

	/*! Rejects larger values. */
	UInt& Maximum(uint64_t maximum);
	/*! Silently reduces larger values to the maximum. */
	UInt& ClampTo(uint64_t maximum);

	rapidjson::Value Schema(detail::Allocator& allocator) const;
	rapidjson::Value DefaultJson(uint64_t value, detail::Allocator& allocator) const;
	std::string MissingMessage() const;
	ArgumentResult<uint64_t> Convert(
		ToolCall& call, const rapidjson::Value& value, const ConvertedArguments& converted) const;
};

/*! A parameter for ToolBuilder::Param, or an item kind for List, that accepts a JSON integer,
	which may be negative.
*/
class Int: public ValueParam<Int, int64_t>
{
	std::optional<int64_t> m_minimum;
	std::optional<int64_t> m_maximum;
	bool m_clamp = false;

public:
	using ValueParam::ValueParam;

	/*! Rejects smaller values. */
	Int& Minimum(int64_t minimum);
	/*! Rejects larger values. */
	Int& Maximum(int64_t maximum);
	/*! Silently moves values outside the range to the nearest bound. */
	Int& ClampTo(int64_t minimum, int64_t maximum);

	rapidjson::Value Schema(detail::Allocator& allocator) const;
	rapidjson::Value DefaultJson(int64_t value, detail::Allocator& allocator) const;
	std::string MissingMessage() const;
	ArgumentResult<int64_t> Convert(
		ToolCall& call, const rapidjson::Value& value, const ConvertedArguments& converted) const;
};

/*! A parameter for ToolBuilder::Param, or an item kind for List, that accepts a JSON number. */
class Number: public ValueParam<Number, double>
{
public:
	using ValueParam::ValueParam;

	rapidjson::Value Schema(detail::Allocator& allocator) const;
	rapidjson::Value DefaultJson(double value, detail::Allocator& allocator) const;
	std::string MissingMessage() const;
	ArgumentResult<double> Convert(
		ToolCall& call, const rapidjson::Value& value, const ConvertedArguments& converted) const;
};

/*! A parameter for ToolBuilder::Param, or an item kind for List, that accepts an address expression
	string, evaluated against the call's binary view.
*/
class Address: public ValueParam<Address, uint64_t>
{
public:
	using ValueParam::ValueParam;

	rapidjson::Value Schema(detail::Allocator& allocator) const;
	rapidjson::Value DefaultJson(uint64_t value, detail::Allocator& allocator) const;
	std::string MissingMessage() const;
	ArgumentResult<uint64_t> Convert(
		ToolCall& call, const rapidjson::Value& value, const ConvertedArguments& converted) const;
};

/*! A parameter for ToolBuilder::Param, or an item kind for List, that accepts an unsigned integer,
	or an expression string evaluated against the call's binary view.
*/
class IntegerExpression: public ValueParam<IntegerExpression, uint64_t>
{
	std::optional<std::string> m_relativeTo;

public:
	using ValueParam::ValueParam;

	/*! Evaluates expressions with the value of the earlier \c Address, \c IntegerExpression, \c UInt
		or \c Int parameter \c name as the current address. When that argument is absent, its default
		is used, or 0 when it has none. Registration fails if \c name is not such a parameter declared
		before this one.
	*/
	IntegerExpression& RelativeTo(std::string name);
	const std::string* GetRelativeTo() const { return m_relativeTo ? &*m_relativeTo : nullptr; }

	rapidjson::Value Schema(detail::Allocator& allocator) const;
	rapidjson::Value DefaultJson(uint64_t value, detail::Allocator& allocator) const;
	std::string MissingMessage() const;
	ArgumentResult<uint64_t> Convert(
		ToolCall& call, const rapidjson::Value& value, const ConvertedArguments& converted) const;
};

/*! A parameter for ToolBuilder::Param, or an item kind for another List, that accepts a JSON array.
	Each item is converted as \c Item would convert a lone argument, such as for
	<tt>List<String></tt>. Pass the item explicitly for a kind that needs settings, such as a
	\c Choice, and name it after the list so that its errors name the parameter.
*/
template <ParamKind Item>
class List: public ValueParam<List<Item>, std::vector<typename Item::Value>>
{
	using Base = ValueParam<List<Item>, std::vector<typename Item::Value>>;

	Item m_item;

public:
	List(std::string name, std::string description)
		requires std::constructible_from<Item, std::string, std::string>
		: Base(name, std::move(description)), m_item(std::move(name), "")
	{
	}

	List(std::string name, std::string description, Item item):
		Base(std::move(name), std::move(description)), m_item(std::move(item))
	{
	}

	const std::string* GetRelativeTo() const { return m_item.GetRelativeTo(); }

	rapidjson::Value Schema(detail::Allocator& allocator) const
	{
		rapidjson::Value schema = detail::TypeSchema("array", allocator);
		rapidjson::Value items = m_item.Schema(allocator);
		schema.AddMember("items", items, allocator);
		detail::AddDescription(schema, this->m_description, allocator);
		return schema;
	}

	rapidjson::Value DefaultJson(const typename Base::Value& value, detail::Allocator& allocator) const
	{
		rapidjson::Value array(rapidjson::kArrayType);
		for (const auto& item : value)
		{
			rapidjson::Value json = m_item.DefaultJson(item, allocator);
			array.PushBack(json, allocator);
		}
		return array;
	}

	std::string MissingMessage() const { return detail::MissingMessage("array", this->m_name); }

	ArgumentResult<typename Base::Value> Convert(
		ToolCall& call, const rapidjson::Value& value, const ConvertedArguments& converted) const
	{
		if (!value.IsArray())
			return bn::base::unexpected(MissingMessage());

		typename Base::Value result;
		result.reserve(value.Size());
		for (const auto& json : value.GetArray())
		{
			ArgumentResult<typename Item::Value> item = m_item.Convert(call, json, converted);
			if (!item)
				return bn::base::unexpected(std::move(item.error()));

			result.push_back(std::move(*item));
		}
		return result;
	}
};

/*! A parameter for ToolBuilder::Param, or an item kind for List, that accepts a core enum value by
	its enumerator name. Core enums cannot be enumerated, so the values the tool accepts are listed
	explicitly.
*/
template <class T>
class Enum: public ValueParam<Enum<T>, T>
{
	std::vector<T> m_values;

	static std::string ValueName(T value)
	{
		return CoreEnumToString(value).value_or(std::to_string(static_cast<std::underlying_type_t<T>>(value)));
	}

public:
	Enum(std::string name, std::string description, std::initializer_list<T> values):
		ValueParam<Enum<T>, T>(std::move(name), std::move(description)), m_values(values)
	{
	}

	rapidjson::Value Schema(detail::Allocator& allocator) const
	{
		rapidjson::Value schema = detail::TypeSchema("string", allocator);
		rapidjson::Value names(rapidjson::kArrayType);
		for (T value : m_values)
		{
			std::string text = ValueName(value);
			names.PushBack(rapidjson::Value(text.c_str(), text.size(), allocator), allocator);
		}
		schema.AddMember("enum", names, allocator);
		detail::AddDescription(schema, this->m_description, allocator);
		return schema;
	}

	rapidjson::Value DefaultJson(T value, detail::Allocator& allocator) const
	{
		std::string text = ValueName(value);
		return rapidjson::Value(text.c_str(), text.size(), allocator);
	}

	std::string MissingMessage() const { return detail::MissingMessage("string", this->m_name); }

	ArgumentResult<T> Convert(ToolCall&, const rapidjson::Value& value, const ConvertedArguments&) const
	{
		if (!value.IsString())
			return bn::base::unexpected(MissingMessage());

		std::optional<T> parsed = CoreEnumFromString<T>(std::string(value.GetString(), value.GetStringLength()));
		if (!parsed || std::find(m_values.begin(), m_values.end(), *parsed) == m_values.end())
			return bn::base::unexpected(fmt::format("Invalid enum value for parameter '{}'", this->m_name));

		return *parsed;
	}
};

/*! A parameter for ToolBuilder::Param that accepts any JSON value matching a caller-supplied schema
	fragment, which carries its own description. It cannot be an item kind for List. The handler
	receives the raw value, or null when an optional argument is absent or null.
*/
class JsonValue: public Param<JsonValue, const rapidjson::Value*>
{
	std::string m_schema;
	bool m_required = true;

public:
	JsonValue(std::string name, std::string schema);

	JsonValue Optional() const;
	bool IsRequired() const { return m_required; }

	void AddSchema(rapidjson::Value& properties, detail::Allocator& allocator) const;
	ArgumentResult<const rapidjson::Value*> Absent() const;
	std::string MissingMessage() const;
	ArgumentResult<const rapidjson::Value*> Convert(
		ToolCall& call, const rapidjson::Value& value, const ConvertedArguments& converted) const;
};

template <class ParseFn, class LookupFn, class... Params>
class GroupParam;

/*! Parameters that are declared separately but passed to the handler as one value, such as a
	function named by an address and an architecture. Call \c Parse, \c Lookup or both before passing
	the group to ToolBuilder::Param.
*/
template <class... Params>
	requires(std::derived_from<Params, detail::SingleProperty<Params>> && ...)
class Group
{
	std::tuple<Params...> m_params;

public:
	explicit Group(Params... params): m_params(std::move(params)...) {}

	/*! Sets the function that combines the arguments into one value. It is called as
		<tt>parse(ToolCall&, Params::Value&...)</tt> and returns an <tt>ArgumentResult<T></tt>. Its
		error is reported as \c invalid_params.
	*/
	template <detail::ParseFunction<typename Params::Value...> ParseFn>
	GroupParam<ParseFn, detail::KeepParsed, Params...> Parse(ParseFn parse) &&
	{
		return {std::move(m_params), std::move(parse), {}};
	}

	/*! Sets the function that finds what the arguments refer to. It is called as
		<tt>lookup(ToolCall&, Params::Value&...)</tt> and returns a
		<tt>bn::base::expected<T, ToolResult></tt>. Its error becomes the tool's result. It runs only
		after every argument has been parsed.
	*/
	template <detail::LookupFunction<typename Params::Value...> LookupFn>
	auto Lookup(LookupFn lookup) &&
	{
		using Arguments = std::tuple<typename Params::Value...>;
		auto lookupArguments = [lookup = std::move(lookup)](ToolCall& call, Arguments& arguments) {
			return std::apply([&](auto&... value) { return lookup(call, value...); }, arguments);
		};
		return GroupParam<detail::KeepArguments, decltype(lookupArguments), Params...> {
			std::move(m_params), {}, std::move(lookupArguments)};
	}
};

/*! Creates a Group with no parameters and the given lookup function. */
template <detail::LookupFunction LookupFn>
auto Lookup(LookupFn lookup)
{
	return Group<>().Lookup(std::move(lookup));
}

/*! A Group that has a parse function, a lookup function or both, created by Group::Parse or
	Group::Lookup.
*/
template <class ParseFn, class LookupFn, class... Params>
class GroupParam
{
	std::tuple<Params...> m_params;
	ParseFn m_parse;
	LookupFn m_lookup;

public:
	using Parsed = typename std::invoke_result_t<const ParseFn&, ToolCall&, typename Params::Value&...>::value_type;
	using Value = typename std::invoke_result_t<const LookupFn&, ToolCall&, Parsed&>::value_type;

	GroupParam(std::tuple<Params...> params, ParseFn parse, LookupFn lookup):
		m_params(std::move(params)), m_parse(std::move(parse)), m_lookup(std::move(lookup))
	{
	}

	/*! Sets the lookup function, which receives the parsed value as <tt>lookup(ToolCall&, Parsed&)</tt>.
		Otherwise it is the same as Group::Lookup.
	*/
	template <detail::LookupFunction<Parsed> NextLookupFn>
	GroupParam<ParseFn, NextLookupFn, Params...> Lookup(NextLookupFn lookup) &&
		requires std::same_as<LookupFn, detail::KeepParsed>
	{
		return {std::move(m_params), std::move(m_parse), std::move(lookup)};
	}

	void Declare(detail::InputSchemaBuilder& schema) const
	{
		std::apply([&](const auto&... param) { (param.Declare(schema), ...); }, m_params);
	}

	ArgumentResult<Parsed> ParseArguments(detail::ArgumentReader& reader) const
	{
		auto arguments = detail::ParseArguments(m_params, reader);
		if (!arguments)
			return bn::base::unexpected(std::move(arguments.error()));

		return std::apply([&](auto&... value) { return m_parse(reader.GetCall(), value...); }, *arguments);
	}

	bn::base::expected<Value, ToolResult> Finish(ToolCall& call, Parsed& parsed) const
	{
		return m_lookup(call, parsed);
	}
};

/*! The types that ToolBuilder::Param accepts. These are the parameter kinds such as String, their
	Optional and Default forms, and a Group after Group::Parse or Group::Lookup.
*/
template <class P>
concept ToolParam = requires(const P& param, detail::InputSchemaBuilder& schema, detail::ArgumentReader& reader,
	ToolCall& call, typename P::Parsed& parsed) {
	typename P::Value;
	param.Declare(schema);
	{ param.ParseArguments(reader) } -> std::same_as<ArgumentResult<typename P::Parsed>>;
	{ param.Finish(call, parsed) } -> std::same_as<bn::base::expected<typename P::Value, ToolResult>>;
};

template <class... Params>
class ToolBuilder
{
	using Values = std::tuple<typename Params::Value...>;

	ToolDefinition m_definition;
	std::tuple<Params...> m_params;

	template <class... Others>
	friend class ToolBuilder;

	ToolBuilder(ToolDefinition definition, std::tuple<Params...> params):
		m_definition(std::move(definition)), m_params(std::move(params))
	{
	}

	// Parse every argument before running any lookup, so that an invalid argument is reported as invalid_params even
	// when a lookup would also fail.
	template <size_t... Index>
	static bn::base::expected<Values, ToolResult> ExtractAll(const std::tuple<Params...>& params, ToolCall& call,
		const rapidjson::Value& arguments, std::index_sequence<Index...>)
	{
		detail::ArgumentReader reader(call, arguments);
		auto parsed = detail::ParseArguments(params, reader);
		if (!parsed)
			return bn::base::unexpected(ToolResult::Error("invalid_params", std::move(parsed.error())));

		std::tuple<std::optional<typename Params::Value>...> values;
		std::optional<ToolResult> error;
		auto finish = [&](auto& slot, const auto& param, auto& value) {
			if (error)
				return;
			auto result = param.Finish(call, value);
			if (result)
				slot.emplace(std::move(*result));
			else
				error = std::move(result.error());
		};
		(finish(std::get<Index>(values), std::get<Index>(params), std::get<Index>(*parsed)), ...);
		if (error)
			return bn::base::unexpected(std::move(*error));
		return Values {std::move(*std::get<Index>(values))...};
	}

public:
	explicit ToolBuilder(ToolDefinition definition)
		requires(sizeof...(Params) == 0)
		: m_definition(std::move(definition))
	{
	}

	template <ToolParam P>
	ToolBuilder<Params..., P> Param(P param) &&
	{
		return ToolBuilder<Params..., P>(
			std::move(m_definition), std::tuple_cat(std::move(m_params), std::make_tuple(std::move(param))));
	}

	/*! Passes the builder to \c transform and continues with what it returns, so that a group of
		parameters shared by several tools can be added in the middle of a chain, as in
		<tt>MakeTool(...).With(ListPaginationParams).Param(...)</tt>.
	*/
	template <class Transform>
	auto With(Transform&& transform) &&
	{
		return std::forward<Transform>(transform)(std::move(*this));
	}

	ToolBuilder OutputSchema(std::string schema) &&
	{
		m_definition.outputSchema = std::move(schema);
		return std::move(*this);
	}

	/*! Registers the tool. The handler is called as <tt>handler(ToolCall&, Params::Value&...)</tt>
		only once every argument has been checked and converted. Missing, invalid and undeclared
		arguments produce an \c invalid_params result instead. Returns null when the parameters or
		the definition are invalid.
	*/
	template <class Handler>
	Ref<Tool> Register(Handler handler) &&
	{
		std::string name = m_definition.name;
		try
		{
			ToolSpec spec = std::move(*this).Build(std::move(handler));
			return RegisterTool(spec.definition, spec.inputSchema, std::move(spec.handler));
		}
		catch (const std::invalid_argument& e)
		{
			detail::LogRejectedTool(name, e.what());
			return nullptr;
		}
	}

	/*! Completes the tool without registering it, such as for an MCP server to create with
		CreateTool. The handler is called as it is for Register. Throws \c std::invalid_argument when
		the parameters are invalid, such as when two share a name or a \c RelativeTo does not name an
		earlier integer parameter.
	*/
	template <class Handler>
	ToolSpec Build(Handler handler) &&
	{
		static_assert(std::is_invocable_r_v<ToolResult, Handler&, ToolCall&, typename Params::Value&...>,
			"The handler must accept (ToolCall&, Params::Value&...) and return a ToolResult");

		detail::InputSchemaBuilder schema(m_definition.name);
		std::apply([&](const auto&... param) { (param.Declare(schema), ...); }, m_params);

		std::string inputSchema = schema.Build();
		ToolHandler toolHandler = [params = std::move(m_params), names = schema.GetNames(),
									  handler = std::move(handler)](
									  ToolCall& call, const rapidjson::Value& arguments) mutable -> ToolResult {
			if (!arguments.IsObject())
				return ToolResult::Error("invalid_params", "Expected object arguments");
			if (auto unexpected = detail::FindUnexpectedArgument(arguments, names))
				return ToolResult::Error("invalid_params", *unexpected);

			auto values = ExtractAll(params, call, arguments, std::index_sequence_for<Params...> {});
			if (!values)
				return std::move(values.error());

			return std::apply([&](auto&... value) -> ToolResult { return handler(call, value...); }, *values);
		};
		return {std::move(m_definition), std::move(inputSchema), std::move(toolHandler)};
	}
};

inline ToolBuilder<> MakeTool(ToolDefinition definition)
{
	return ToolBuilder<>(std::move(definition));
}
}  // namespace BinaryNinja::MCP
