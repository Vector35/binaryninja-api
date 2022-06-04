#pragma once

#include <string>
#include <vector>
#include <typeinfo>
#include <variant>
#include "confidence.hpp"
#include "refcount.hpp"
#include "workflow.h"

namespace BinaryNinja
{
	class FlowGraph;
	class Activity;
	class Workflow : public CoreRefCountObject<BNWorkflow, BNNewWorkflowReference, BNFreeWorkflow>
	{
	  public:
		Workflow(const std::string& name = "");
		Workflow(BNWorkflow* workflow);
		virtual ~Workflow() {}

		static std::vector<Ref<Workflow>> GetList();
		static Ref<Workflow> Instance(const std::string& name = "");
		static bool RegisterWorkflow(Ref<Workflow> workflow, const std::string& description = "");

		Ref<Workflow> Clone(const std::string& name, const std::string& activity = "");
		bool RegisterActivity(Ref<Activity> activity, const std::string& description = "");
		bool RegisterActivity(Ref<Activity> activity, std::initializer_list<const char*> initializer)
		{
			return RegisterActivity(activity, std::vector<std::string>(initializer.begin(), initializer.end()));
		}
		bool RegisterActivity(
			Ref<Activity> activity, const std::vector<std::string>& subactivities, const std::string& description = "");

		bool Contains(const std::string& activity);
		std::string GetConfiguration(const std::string& activity = "");
		std::string GetName() const;
		bool IsRegistered() const;
		size_t Size() const;

		Ref<Activity> GetActivity(const std::string& activity);
		std::vector<std::string> GetActivityRoots(const std::string& activity = "");
		std::vector<std::string> GetSubactivities(const std::string& activity = "", bool immediate = true);
		bool AssignSubactivities(const std::string& activity, const std::vector<std::string>& subactivities = {});
		bool Clear();
		bool Insert(const std::string& activity, const std::string& newActivity);
		bool Insert(const std::string& activity, const std::vector<std::string>& activities);
		bool Remove(const std::string& activity);
		bool Replace(const std::string& activity, const std::string& newActivity);

		Ref<FlowGraph> GetGraph(const std::string& activity = "", bool sequential = false);
		void ShowReport(const std::string& name);

		// bool Run(const std::string& activity, Ref<AnalysisContext> analysisContext);
	};
}