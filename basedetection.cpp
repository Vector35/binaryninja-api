// Copyright (c) 2015-2024 Vector 35 Inc
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

#include "binaryninjaapi.h"

using namespace BinaryNinja;


BaseAddressDetection::BaseAddressDetection(Ref<BinaryView> bv)
{
    m_object = BNCreateBaseAddressDetection(bv->GetObject());
}


BaseAddressDetection::~BaseAddressDetection()
{
    BNFreeBaseAddressDetection(m_object);
}


bool BaseAddressDetection::DetectBaseAddress(BaseAddressDetectionSettings& settings)
{
    BNBaseAddressDetectionSettings bnSettings = {
        settings.Architecture.c_str(),
        settings.Analysis.c_str(),
        settings.MinStrlen,
        settings.Alignment,
        settings.LowerBoundary,
        settings.UpperBoundary,
        settings.POIAnalysis,
        settings.MaxPointersPerCluster,
    };

    return BNDetectBaseAddress(m_object, bnSettings);
}


void BaseAddressDetection::Abort()
{
    return BNAbortBaseAddressDetection(m_object);
}


bool BaseAddressDetection::IsAborted()
{
    return BNIsBaseAddressDetectionAborted(m_object);
}


std::set<std::pair<size_t, uint64_t>> BaseAddressDetection::GetScores(BNBaseAddressDetectionConfidence* confidence,
    uint64_t *lastTestedBaseAddress)
{
    std::set<std::pair<size_t, uint64_t>> result;
    BNBaseAddressDetectionScore scores[10];
    size_t numCandidates = BNGetBaseAddressDetectionScores(m_object, scores, 10, confidence, lastTestedBaseAddress);
    for (size_t i = 0; i < numCandidates; i++)
        result.insert(std::make_pair(scores[i].Score, scores[i].BaseAddress));
    return result;
}


std::vector<BNBaseAddressDetectionReason> BaseAddressDetection::GetReasonsForBaseAddress(uint64_t baseAddress)
{
    std::vector<BNBaseAddressDetectionReason> result;
    size_t count;
    BNBaseAddressDetectionReason *reasons = BNGetBaseAddressDetectionReasons(m_object, baseAddress, &count);
    if (!reasons)
        return result;

    for (size_t i = 0; i < count; i++)
        result.push_back(reasons[i]);

    free(reasons);
    return result;
}
