#pragma once

#include <string>
#include <vector>
#include "activity.h"
#include "json/json.h"
#include "confidence.hpp"

namespace BinaryNinja
{
	class Architecture;
	class BasicBlock;
	class Function;
	class LowLevelILFunction;
	class MediumLevelILFunction;
	class HighLevelILFunction;
	class DelegateInterface;
	class AnalysisContext;

	class AnalysisContext :
		public CoreRefCountObject<BNAnalysisContext, BNNewAnalysisContextReference, BNFreeAnalysisContext>
	{
		std::unique_ptr<Json::CharReader> m_reader;
		Json::StreamWriterBuilder m_builder;

	  public:
		AnalysisContext(BNAnalysisContext* analysisContext);
		virtual ~AnalysisContext();

		Ref<Function> GetFunction();
		Ref<LowLevelILFunction> GetLowLevelILFunction();
		Ref<MediumLevelILFunction> GetMediumLevelILFunction();
		Ref<HighLevelILFunction> GetHighLevelILFunction();

		void SetBasicBlockList(std::vector<Ref<BasicBlock>> basicBlocks);
		void SetLiftedILFunction(Ref<LowLevelILFunction> liftedIL);
		void SetLowLevelILFunction(Ref<LowLevelILFunction> lowLevelIL);
		void SetMediumLevelILFunction(Ref<MediumLevelILFunction> mediumLevelIL);
		void SetHighLevelILFunction(Ref<HighLevelILFunction> highLevelIL);

		bool Inform(const std::string& request);
#if ((__cplusplus >= 201403L) || (_MSVC_LANG >= 201703L))
		template <typename... Args> 
		bool Inform(Args... args);
#endif
	};

	class Activity : public CoreRefCountObject<BNActivity, BNNewActivityReference, BNFreeActivity>
	{
	  protected:
		std::function<void(Ref<AnalysisContext> analysisContext)> m_action;

		static void Run(void* ctxt, BNAnalysisContext* analysisContext);

	  public:
		Activity(const std::string& name, const std::function<void(Ref<AnalysisContext>)>& action);
		Activity(BNActivity* activity);
		virtual ~Activity();

		std::string GetName() const;
	};
}