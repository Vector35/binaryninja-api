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

#include "mcp.h"

#include "mcpserver.h"
#include "rapidjsonwrapper.h"

#include <exception>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace BinaryNinja;
using namespace BinaryNinja::MCP;

namespace {

Ref<Logger> GetMcpLogger()
{
	static Ref<Logger> logger = LogRegistry::CreateLogger("MCP");
	return logger;
}

std::string TakeString(char* text)
{
	std::string result = text ? text : "";
	BNFreeString(text);
	return result;
}

ArgumentResult<uint64_t> ParseWith(bool (*parse)(BNMcpToolCall*, const char*, uint64_t*, uint64_t, char**),
	BNMcpToolCall* call, const rapidjson::Value& value, uint64_t here)
{
	std::string json = detail::SerializeJson(value);
	uint64_t result = 0;
	char* error = nullptr;
	if (!parse(call, json.c_str(), &result, here, &error))
		return bn::base::unexpected(TakeString(error));

	return result;
}

void InvokeHandler(void* ctxt, BNMcpToolCall* callHandle, const char* arguments, BNMcpToolResult* result)
{
	auto& handler = *static_cast<ToolHandler*>(ctxt);
	Ref<ToolCall> call = new ToolCall(BNNewMcpToolCallReference(callHandle));
	rapidjson::Document document;
	try
	{
		document.Parse(arguments);
	}
	catch (const ParseException& e)
	{
		ToolResult::Error("invalid_params", fmt::format("Arguments are not valid JSON: {}", e.what())).ApplyTo(result);
		return;
	}

	std::optional<ToolResult> toolResult;
	try
	{
		toolResult = handler(*call, document);
	}
	catch (const std::exception& e)
	{
		GetMcpLogger()->LogErrorForExceptionF(e, "MCP tool failed: {}", e.what());
		toolResult = ToolResult::Error("internal_error", e.what());
	}
	catch (...)
	{
		GetMcpLogger()->LogError("MCP tool failed with an unknown exception");
		toolResult = ToolResult::Error("internal_error", "The tool failed with an unknown exception");
	}
	toolResult->ApplyTo(result);
}

Ref<Tool> CreateToolUsing(const ToolDefinition& definition, const std::string& inputSchema, ToolHandler handler,
	BNMcpTool* (*create)(const BNMcpToolDefinition*, const BNMcpToolCallbacks*))
{
	BNMcpToolDefinition apiDefinition = {};
	apiDefinition.name = definition.name.c_str();
	apiDefinition.title = definition.title.c_str();
	apiDefinition.description = definition.description.c_str();
	apiDefinition.inputSchema = inputSchema.c_str();
	apiDefinition.outputSchema = definition.outputSchema.empty() ? nullptr : definition.outputSchema.c_str();
	apiDefinition.scope = static_cast<BNMcpToolScope>(definition.scope);
	apiDefinition.annotations = definition.annotations;

	auto* context = new ToolHandler(std::move(handler));
	BNMcpToolCallbacks callbacks = {};
	callbacks.context = context;
	callbacks.invoke = InvokeHandler;
	callbacks.freeObject = [](void* ctxt) { delete static_cast<ToolHandler*>(ctxt); };
	BNMcpTool* tool = create(&apiDefinition, &callbacks);
	if (!tool)
	{
		delete context;
		return nullptr;
	}

	return new Tool(tool);
}
}  // namespace


ToolCall::ToolCall(BNMcpToolCall* call)
{
	m_object = call;
}


Ref<BinaryView> ToolCall::GetBinaryView() const
{
	BNBinaryView* view = BNGetMcpToolCallBinaryView(m_object);
	return view ? new BinaryView(view) : nullptr;
}


bool ToolCall::IsCancelled() const
{
	return BNIsMcpToolCallCancelled(m_object);
}


void ToolCall::ReportProgress(double progress, double total, const std::string& message) const
{
	BNReportMcpToolCallProgress(m_object, progress, total, message.c_str());
}


ArgumentResult<uint64_t> ToolCall::ParseAddress(const rapidjson::Value& value, uint64_t here) const
{
	return ParseWith(BNParseMcpToolCallAddress, m_object, value, here);
}


ArgumentResult<uint64_t> ToolCall::ParseInteger(const rapidjson::Value& value, uint64_t here) const
{
	return ParseWith(BNParseMcpToolCallInteger, m_object, value, here);
}


ToolResult ToolResult::Text(std::string text)
{
	ToolResult result;
	result.m_text.push_back(std::move(text));
	return result;
}


ToolResult ToolResult::Structured(const rapidjson::Value& content)
{
	ToolResult result;
	result.m_structuredContent = detail::SerializeJson(content);
	return result;
}


ToolResult ToolResult::Error(std::string code, std::string message, const rapidjson::Value* details)
{
	ToolResult result;
	result.m_error = ErrorInfo {std::move(code), std::move(message),
		details ? std::optional(detail::SerializeJson(*details)) : std::nullopt};
	return result;
}


ToolResult& ToolResult::AddText(std::string text)
{
	m_text.push_back(std::move(text));
	return *this;
}


ToolResult& ToolResult::AddWarning(std::string code, std::string message)
{
	m_warnings.emplace_back(std::move(code), std::move(message));
	return *this;
}


void ToolResult::ApplyTo(BNMcpToolResult* result) const
{
	if (m_error)
	{
		BNSetMcpToolResultError(result, m_error->code.c_str(), m_error->message.c_str(),
			m_error->details ? m_error->details->c_str() : nullptr);
	}
	else if (m_structuredContent && !BNSetMcpToolResultStructuredContent(result, m_structuredContent->c_str()))
	{
		BNSetMcpToolResultError(
			result, "internal_error", "The tool produced structured content that is not a JSON object", nullptr);
		return;
	}

	for (const auto& text : m_text)
		BNAddMcpToolResultText(result, text.c_str());
	for (const auto& [code, message] : m_warnings)
		BNAddMcpToolResultWarning(result, code.c_str(), message.c_str());
}


std::string ToolResult::ToJson() const
{
	BNMcpToolResult* result = BNCreateMcpToolResult();
	ApplyTo(result);
	std::string json = TakeString(BNGetMcpToolResultJson(result));
	BNFreeMcpToolResult(result);
	return json;
}


Tool::Tool(BNMcpTool* tool)
{
	m_object = tool;
}


std::vector<Ref<Tool>> Tool::GetList()
{
	size_t count = 0;
	BNMcpTool** tools = BNGetMcpToolList(&count);

	std::vector<Ref<Tool>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Tool(BNNewMcpToolReference(tools[i])));

	BNFreeMcpToolList(tools, count);
	return result;
}


Ref<Tool> Tool::GetByName(const std::string& name)
{
	BNMcpTool* tool = BNGetMcpToolByName(name.c_str());
	return tool ? new Tool(tool) : nullptr;
}


std::string Tool::GetName() const
{
	return TakeString(BNGetMcpToolName(m_object));
}


std::string Tool::GetTitle() const
{
	return TakeString(BNGetMcpToolTitle(m_object));
}


std::string Tool::GetDescription() const
{
	return TakeString(BNGetMcpToolDescription(m_object));
}


std::string Tool::GetInputSchema() const
{
	return TakeString(BNGetMcpToolInputSchema(m_object));
}


std::string Tool::GetOutputSchema() const
{
	return TakeString(BNGetMcpToolOutputSchema(m_object));
}


Scope Tool::GetScope() const
{
	return static_cast<Scope>(BNGetMcpToolScope(m_object));
}


uint32_t Tool::GetAnnotations() const
{
	return BNGetMcpToolAnnotations(m_object);
}


std::string BinaryNinja::MCP::InvokeTool(
	Tool& tool, ToolCallHost& host, const std::string& arguments, const ToolResult* error)
{
	BNMcpToolCallCallbacks callbacks = {};
	callbacks.context = &host;
	callbacks.getBinaryView = [](void* ctxt) -> BNBinaryView* {
		try
		{
			Ref<BinaryView> view = static_cast<ToolCallHost*>(ctxt)->GetBinaryView();
			return view ? BNNewViewReference(view->GetObject()) : nullptr;
		}
		catch (const std::exception& e)
		{
			GetMcpLogger()->LogErrorForExceptionF(e, "MCP host failed to supply a binary view: {}", e.what());
			return nullptr;
		}
	};
	callbacks.isCancelled = [](void* ctxt) {
		try
		{
			return static_cast<ToolCallHost*>(ctxt)->IsCancelled();
		}
		catch (const std::exception& e)
		{
			GetMcpLogger()->LogErrorForExceptionF(e, "MCP host failed to report cancellation: {}", e.what());
			return false;
		}
	};
	callbacks.reportProgress = [](void* ctxt, double progress, double total, const char* message) {
		try
		{
			static_cast<ToolCallHost*>(ctxt)->ReportProgress(progress, total, message);
		}
		catch (const std::exception& e)
		{
			GetMcpLogger()->LogErrorForExceptionF(e, "MCP host failed to receive progress: {}", e.what());
		}
	};

	BNMcpToolCall* call = BNCreateMcpToolCall(&callbacks);
	BNMcpToolResult* result = BNCreateMcpToolResult();
	if (error)
		error->ApplyTo(result);
	BNInvokeMcpTool(tool.GetObject(), call, arguments.c_str(), result);
	std::string json = TakeString(BNGetMcpToolResultJson(result));
	BNFreeMcpToolResult(result);
	BNFreeMcpToolCall(call);
	return json;
}


Ref<Tool> BinaryNinja::MCP::RegisterTool(
	const ToolDefinition& definition, const std::string& inputSchema, ToolHandler handler)
{
	return CreateToolUsing(definition, inputSchema, std::move(handler), BNRegisterMcpTool);
}


Ref<Tool> BinaryNinja::MCP::CreateTool(ToolSpec spec)
{
	return CreateToolUsing(spec.definition, spec.inputSchema, std::move(spec.handler), BNCreateMcpTool);
}


void detail::AddProperty(
	rapidjson::Value& properties, std::string_view name, rapidjson::Value& schema, Allocator& allocator)
{
	properties.AddMember(rapidjson::Value(name.data(), name.size(), allocator), schema, allocator);
}


rapidjson::Value detail::TypeSchema(const char* type, Allocator& allocator)
{
	rapidjson::Value schema(rapidjson::kObjectType);
	schema.AddMember("type", rapidjson::StringRef(type), allocator);
	return schema;
}


void detail::AddDescription(rapidjson::Value& schema, std::string_view description, Allocator& allocator)
{
	if (description.empty())
		return;

	schema.AddMember("description", rapidjson::Value(description.data(), description.size(), allocator), allocator);
}


std::string detail::MissingMessage(std::string_view kind, std::string_view name)
{
	return fmt::format("Expected {} parameter '{}'", kind, name);
}


std::string detail::SerializeJson(const rapidjson::Value& value)
{
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	value.Accept(writer);
	return std::string(buffer.GetString(), buffer.GetSize());
}


std::optional<std::string> detail::FindUnexpectedArgument(
	const rapidjson::Value& arguments, const std::vector<std::string>& names)
{
	for (const auto& member : arguments.GetObj())
	{
		std::string_view name(member.name.GetString(), member.name.GetStringLength());
		if (std::ranges::find(names, name) == names.end())
			return fmt::format("Unexpected parameter '{}'", name);
	}
	return std::nullopt;
}


void detail::LogRejectedTool(std::string_view name, std::string_view reason)
{
	GetMcpLogger()->LogErrorF("Rejected MCP tool '{}': {}", name, reason);
}


detail::InputSchemaBuilder::InputSchemaBuilder(std::string tool):
	m_tool(std::move(tool)), m_schema(rapidjson::kObjectType), m_properties(rapidjson::kObjectType),
	m_required(rapidjson::kArrayType)
{
}


void detail::InputSchemaBuilder::Add(
	const std::string& name, bool required, const std::string* relativeTo, bool integer)
{
	if (std::ranges::find(m_names, name) != m_names.end())
		throw std::invalid_argument(fmt::format("MCP tool '{}' declares parameter '{}' more than once", m_tool, name));

	if (relativeTo && std::ranges::find(m_integerNames, *relativeTo) == m_integerNames.end())
	{
		throw std::invalid_argument(fmt::format(
			"MCP tool '{}' parameter '{}' is relative to '{}', which must be an integer parameter declared before it",
			m_tool, name, *relativeTo));
	}

	m_names.push_back(name);
	if (integer)
		m_integerNames.push_back(name);

	if (required)
		m_required.PushBack(rapidjson::Value(name.c_str(), name.size(), GetAllocator()), GetAllocator());
}


std::string detail::InputSchemaBuilder::Build()
{
	auto& allocator = GetAllocator();
	m_schema.AddMember("type", "object", allocator);
	m_schema.AddMember("properties", m_properties, allocator);
	if (!m_required.Empty())
		m_schema.AddMember("required", m_required, allocator);
	m_schema.AddMember("additionalProperties", false, allocator);
	return SerializeJson(m_schema);
}


String& String::NonEmpty()
{
	m_nonEmpty = true;
	return *this;
}


rapidjson::Value String::Schema(detail::Allocator& allocator) const
{
	rapidjson::Value schema = detail::TypeSchema("string", allocator);
	if (m_nonEmpty)
		schema.AddMember("minLength", 1, allocator);

	detail::AddDescription(schema, m_description, allocator);
	return schema;
}


rapidjson::Value String::DefaultJson(std::string_view value, detail::Allocator& allocator) const
{
	return rapidjson::Value(value.data(), value.size(), allocator);
}


std::string String::MissingMessage() const
{
	return detail::MissingMessage(m_nonEmpty ? "non-empty string" : "string", m_name);
}


ArgumentResult<std::string> String::Convert(ToolCall&, const rapidjson::Value& value, const ConvertedArguments&) const
{
	if (!value.IsString() || (m_nonEmpty && value.GetStringLength() == 0))
		return bn::base::unexpected(MissingMessage());

	return std::string(value.GetString(), value.GetStringLength());
}


Choice::Choice(std::string name, std::string description, std::vector<std::string> choices):
	ValueParam(std::move(name), std::move(description)), m_choices(std::move(choices))
{
}


rapidjson::Value Choice::Schema(detail::Allocator& allocator) const
{
	rapidjson::Value schema = detail::TypeSchema("string", allocator);
	rapidjson::Value choices(rapidjson::kArrayType);
	for (const auto& choice : m_choices)
		choices.PushBack(rapidjson::Value(choice.c_str(), choice.size(), allocator), allocator);
	schema.AddMember("enum", choices, allocator);
	detail::AddDescription(schema, m_description, allocator);
	return schema;
}


rapidjson::Value Choice::DefaultJson(std::string_view value, detail::Allocator& allocator) const
{
	return rapidjson::Value(value.data(), value.size(), allocator);
}


std::string Choice::MissingMessage() const
{
	return detail::MissingMessage("string", m_name);
}


ArgumentResult<std::string> Choice::Convert(ToolCall&, const rapidjson::Value& value, const ConvertedArguments&) const
{
	if (!value.IsString())
		return bn::base::unexpected(MissingMessage());

	std::string text(value.GetString(), value.GetStringLength());
	if (std::find(m_choices.begin(), m_choices.end(), text) == m_choices.end())
		return bn::base::unexpected(fmt::format("Invalid enum value for parameter '{}'", m_name));
	return text;
}


rapidjson::Value Bool::Schema(detail::Allocator& allocator) const
{
	rapidjson::Value schema = detail::TypeSchema("boolean", allocator);
	detail::AddDescription(schema, m_description, allocator);
	return schema;
}


rapidjson::Value Bool::DefaultJson(bool value, detail::Allocator&) const
{
	return rapidjson::Value(value);
}


std::string Bool::MissingMessage() const
{
	return detail::MissingMessage("boolean", m_name);
}


ArgumentResult<bool> Bool::Convert(ToolCall&, const rapidjson::Value& value, const ConvertedArguments&) const
{
	if (!value.IsBool())
		return bn::base::unexpected(MissingMessage());

	return value.GetBool();
}


UInt& UInt::Maximum(uint64_t maximum)
{
	m_maximum = maximum;
	m_clamp = false;
	return *this;
}


UInt& UInt::ClampTo(uint64_t maximum)
{
	m_maximum = maximum;
	m_clamp = true;
	return *this;
}


rapidjson::Value UInt::Schema(detail::Allocator& allocator) const
{
	rapidjson::Value schema = detail::TypeSchema("integer", allocator);
	schema.AddMember("minimum", 0, allocator);
	if (m_maximum)
		schema.AddMember("maximum", rapidjson::Value().SetUint64(*m_maximum), allocator);

	detail::AddDescription(schema, m_description, allocator);
	return schema;
}


rapidjson::Value UInt::DefaultJson(uint64_t value, detail::Allocator&) const
{
	return rapidjson::Value(value);
}


std::string UInt::MissingMessage() const
{
	return detail::MissingMessage("unsigned integer", m_name);
}


ArgumentResult<uint64_t> UInt::Convert(ToolCall&, const rapidjson::Value& value, const ConvertedArguments&) const
{
	if (!value.IsUint64())
		return bn::base::unexpected(MissingMessage());

	uint64_t result = value.GetUint64();
	if (m_maximum && result > *m_maximum)
	{
		if (m_clamp)
			return *m_maximum;

		return bn::base::unexpected(
			fmt::format("Invalid unsigned integer parameter '{}': Must be at most {}", m_name, *m_maximum));
	}
	return result;
}


Int& Int::Minimum(int64_t minimum)
{
	m_minimum = minimum;
	m_clamp = false;
	return *this;
}


Int& Int::Maximum(int64_t maximum)
{
	m_maximum = maximum;
	m_clamp = false;
	return *this;
}


Int& Int::ClampTo(int64_t minimum, int64_t maximum)
{
	m_minimum = minimum;
	m_maximum = maximum;
	m_clamp = true;
	return *this;
}


rapidjson::Value Int::Schema(detail::Allocator& allocator) const
{
	rapidjson::Value schema = detail::TypeSchema("integer", allocator);
	if (m_minimum)
		schema.AddMember("minimum", rapidjson::Value().SetInt64(*m_minimum), allocator);
	if (m_maximum)
		schema.AddMember("maximum", rapidjson::Value().SetInt64(*m_maximum), allocator);
	detail::AddDescription(schema, m_description, allocator);
	return schema;
}


rapidjson::Value Int::DefaultJson(int64_t value, detail::Allocator&) const
{
	return rapidjson::Value(value);
}


std::string Int::MissingMessage() const
{
	return detail::MissingMessage("integer", m_name);
}


ArgumentResult<int64_t> Int::Convert(ToolCall&, const rapidjson::Value& value, const ConvertedArguments&) const
{
	if (!value.IsInt64())
		return bn::base::unexpected(MissingMessage());

	int64_t result = value.GetInt64();
	if (m_minimum && result < *m_minimum)
	{
		if (m_clamp)
			return *m_minimum;
		return bn::base::unexpected(
			fmt::format("Invalid integer parameter '{}': Must be at least {}", m_name, *m_minimum));
	}
	if (m_maximum && result > *m_maximum)
	{
		if (m_clamp)
			return *m_maximum;
		return bn::base::unexpected(
			fmt::format("Invalid integer parameter '{}': Must be at most {}", m_name, *m_maximum));
	}
	return result;
}


rapidjson::Value Number::Schema(detail::Allocator& allocator) const
{
	rapidjson::Value schema = detail::TypeSchema("number", allocator);
	detail::AddDescription(schema, m_description, allocator);
	return schema;
}


rapidjson::Value Number::DefaultJson(double value, detail::Allocator&) const
{
	return rapidjson::Value(value);
}


std::string Number::MissingMessage() const
{
	return detail::MissingMessage("number", m_name);
}


ArgumentResult<double> Number::Convert(ToolCall&, const rapidjson::Value& value, const ConvertedArguments&) const
{
	if (!value.IsNumber())
		return bn::base::unexpected(MissingMessage());

	return value.GetDouble();
}


rapidjson::Value Address::Schema(detail::Allocator& allocator) const
{
	rapidjson::Value schema = detail::TypeSchema("string", allocator);
	detail::AddDescription(schema, m_description, allocator);
	return schema;
}


rapidjson::Value Address::DefaultJson(uint64_t value, detail::Allocator& allocator) const
{
	std::string text = fmt::format("{:#x}", value);
	return rapidjson::Value(text.c_str(), text.size(), allocator);
}


std::string Address::MissingMessage() const
{
	return detail::MissingMessage("address expression", m_name);
}


ArgumentResult<uint64_t> Address::Convert(
	ToolCall& call, const rapidjson::Value& value, const ConvertedArguments&) const
{
	auto address = call.ParseAddress(value);
	if (!address)
		return bn::base::unexpected(
			fmt::format("Invalid address expression parameter '{}': {}", m_name, address.error()));

	return address;
}


rapidjson::Value IntegerExpression::Schema(detail::Allocator& allocator) const
{
	rapidjson::Value schema(rapidjson::kObjectType);
	rapidjson::Value types(rapidjson::kArrayType);
	types.PushBack(rapidjson::StringRef("integer"), allocator);
	types.PushBack(rapidjson::StringRef("string"), allocator);
	schema.AddMember("type", types, allocator);
	schema.AddMember("minimum", 0, allocator);
	detail::AddDescription(schema, m_description, allocator);
	return schema;
}


rapidjson::Value IntegerExpression::DefaultJson(uint64_t value, detail::Allocator&) const
{
	return rapidjson::Value(value);
}


std::string IntegerExpression::MissingMessage() const
{
	return detail::MissingMessage("unsigned integer", m_name);
}


IntegerExpression& IntegerExpression::RelativeTo(std::string name)
{
	m_relativeTo = std::move(name);
	return *this;
}


ArgumentResult<uint64_t> IntegerExpression::Convert(
	ToolCall& call, const rapidjson::Value& value, const ConvertedArguments& converted) const
{
	uint64_t here = m_relativeTo ? converted.Get(*m_relativeTo).value_or(0) : 0;
	auto integer = call.ParseInteger(value, here);
	if (!integer)
		return bn::base::unexpected(
			fmt::format("Invalid unsigned integer parameter '{}': {}", m_name, integer.error()));
	return integer;
}


JsonValue::JsonValue(std::string name, std::string schema): Param(std::move(name), ""), m_schema(std::move(schema)) {}


JsonValue JsonValue::Optional() const
{
	JsonValue result = *this;
	result.m_required = false;
	return result;
}


void JsonValue::AddSchema(rapidjson::Value& properties, detail::Allocator& allocator) const
{
	rapidjson::Document fragment;
	try
	{
		fragment.Parse(m_schema.c_str());
	}
	catch (const ParseException&)
	{
		throw std::invalid_argument(fmt::format("The schema for MCP tool parameter '{}' is not valid JSON", m_name));
	}
	rapidjson::Value schema(fragment, allocator);
	detail::AddProperty(properties, m_name, schema, allocator);
}


ArgumentResult<const rapidjson::Value*> JsonValue::Absent() const
{
	if (m_required)
		return bn::base::unexpected(MissingMessage());

	return nullptr;
}


std::string JsonValue::MissingMessage() const
{
	return fmt::format("Expected parameter '{}'", m_name);
}


ArgumentResult<const rapidjson::Value*> JsonValue::Convert(
	ToolCall&, const rapidjson::Value& value, const ConvertedArguments&) const
{
	return &value;
}
