#pragma once
#include "refcount.hpp"
#include "analysis.h"

namespace BinaryNinja {
	class Function;
	struct ActiveAnalysisInfo
	{
		Ref<Function> func;
		uint64_t analysisTime;
		size_t updateCount;
		size_t submitCount;

		ActiveAnalysisInfo(Ref<Function> f, uint64_t t, size_t uc, size_t sc) :
		    func(f), analysisTime(t), updateCount(uc), submitCount(sc)
		{}
	};

	struct AnalysisInfo
	{
		BNAnalysisState state;
		uint64_t analysisTime;
		std::vector<ActiveAnalysisInfo> activeInfo;
	};
}