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

#include "binaryninjaapi.h"
#include "mcp.h"

#include <string>
#include <string_view>

namespace BinaryNinja::MCP {

/*! The request state an MCP server supplies for one invocation of a tool. */
class ToolCallHost
{
public:
	virtual ~ToolCallHost() = default;

	virtual Ref<BinaryNinja::BinaryView> GetBinaryView() = 0;
	virtual bool IsCancelled() { return false; }
	virtual void ReportProgress(double progress, double total, std::string_view message) {}
};

/*! Creates a tool without registering it. This can be used to expose a tool that is specific to
	one MCP server, such as one that manages that server's active binary view. Returns null when the
	definition is invalid.
*/
Ref<Tool> CreateTool(ToolSpec spec);

/*! Runs the tool for an MCP server and returns an MCP CallToolResult as JSON. An \c error result, when
	given, is returned in place of running the tool, finished as the tool's own error would be. This
	lets a server give its own reason for refusing a call, such as why it has no binary view.
*/
std::string InvokeTool(
	Tool& tool, ToolCallHost& host, const std::string& arguments, const ToolResult* error = nullptr);
}  // namespace BinaryNinja::MCP
