/*
Copyright 2020-2026 Vector 35 Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "binaryninjaapi.h"

using namespace BinaryNinja;

static void RegisterSettings()
{
	Ref<Settings> settings = Settings::Instance();

	settings->RegisterSetting("emulator.builtinLibcStubs",
		R"~({
		"title" : "Built-in Libc Stubs",
		"type" : "boolean",
		"default" : true,
		"description" : "Enable built-in stub implementations for common C library and Windows API functions (memcpy, strlen, malloc, VirtualAlloc, etc.) during LLIL emulation. When enabled, the emulator can continue through calls to these functions without stopping."
		})~");

	settings->RegisterSetting("emulator.logLibcCalls",
		R"~({
		"title" : "Log Libc Stub Calls",
		"type" : "boolean",
		"default" : true,
		"description" : "Log built-in libc stub invocations to the console during LLIL emulation. Messages include function name and argument values."
		})~");
}

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN void CorePluginDependencies() {}

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		LogDebug("BNIL emulator plugin loaded!");
		RegisterSettings();
		return true;
	}
}
