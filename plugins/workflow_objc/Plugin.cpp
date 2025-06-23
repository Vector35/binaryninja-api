/*
 * Copyright (c) 2022-2023 Jon Palmisciano. All rights reserved.
 *
 * Use of this source code is governed by the BSD 3-Clause license; the full
 * terms of the license can be found in the LICENSE.txt file.
 */

#include "Constants.h"
#include "Workflow.h"

extern "C" {

BN_DECLARE_CORE_ABI_VERSION

BINARYNINJAPLUGIN void CorePluginDependencies()
{
    BinaryNinja::AddOptionalPluginDependency("arch_x86");
    BinaryNinja::AddOptionalPluginDependency("arch_armv7");
    BinaryNinja::AddOptionalPluginDependency("arch_arm64");
}

BINARYNINJAPLUGIN bool CorePluginInit()
{
    Workflow::registerActivities();

    std::vector<BinaryNinja::Ref<BinaryNinja::Architecture>> targets = {
        BinaryNinja::Architecture::GetByName("aarch64"),
        BinaryNinja::Architecture::GetByName("x86_64")
    };

    BinaryNinja::LogRegistry::CreateLogger(PluginLoggerName);

    auto settings = BinaryNinja::Settings::Instance();
    settings->RegisterSetting("core.function.objectiveC.rewriteMessageSendTarget",
        R"({
		"title" : "Rewrite objc_msgSend calls in IL",
		"type" : "boolean",
		"default" : false,
		"description" : "Message sends of selectors with any visible implementation are replaced with a direct call to the first visible implementation. Note that this can produce false positives if the selector is implemented by more than one class, or shares a name with a method from a system framework."
		})");

    return true;
}
}
