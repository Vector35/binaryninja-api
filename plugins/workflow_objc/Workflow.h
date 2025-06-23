/*
 * Copyright (c) 2022-2023 Jon Palmisciano. All rights reserved.
 *
 * Use of this source code is governed by the BSD 3-Clause license; the full
 * terms of the license can be found in the LICENSE.txt file.
 */

#pragma once

#include "BinaryNinja.h"

/**
 * Namespace to hold activity ID constants.
 */
namespace ActivityID {

constexpr auto ResolveMethodCalls = "core.function.objectiveC.resolveMethodCalls";

}

/**
 * Workflow-related procedures.
 */
class Workflow {

    /**
     * Attempt to rewrite the `objc_msgSend` call at `insnIndex` with a direct
     * call to the requested method's implementation.
     *
     * @param insnIndex The index of the `LLIL_CALL` instruction to rewrite
     */
    static bool rewriteMethodCall(LLILFunctionRef, size_t insnIndex);

public:
    /**
     * Attempt to inline all `objc_msgSend` calls in the given analysis context.
     */
    static void inlineMethodCalls(AnalysisContextRef);

    /**
     * Register the Objective Ninja workflow and all activities.
     *
     * This is named a bit strangely because `register` is a keyword in C++ and
     * therefore an invalid method name, and I refuse to misspell it to appease
     * the compiler and avoid the conflict.
     */
    static void registerActivities();
};
