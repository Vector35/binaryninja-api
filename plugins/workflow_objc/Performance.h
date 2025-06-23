/*
 * Copyright (c) 2022-2023 Jon Palmisciano. All rights reserved.
 *
 * Use of this source code is governed by the BSD 3-Clause license; the full
 * terms of the license can be found in the LICENSE.txt file.
 */

#pragma once

#include <chrono>

using high_res_clock = std::chrono::high_resolution_clock;

/**
 * Utilities for measuring performance.
 */
class Performance {
public:
    /**
     * Get the current time.
     */
    static high_res_clock::time_point now()
    {
        return high_res_clock::now();
    }

    /**
     * Get the current elapsed time from a given start time.
     *
     * Accepts a unit of measure template parameter for the result.
     */
    template <typename T>
    static T elapsed(high_res_clock::time_point start)
    {
        auto end = high_res_clock::now();
        return std::chrono::duration_cast<T>(end - start);
    }
};
