#pragma once

#include "architecture.h"
#include "binaryninjacore.h"
#include "refcount.h"
#include "json/json.h"
#include <functional>
#include <memory>
#include <variant>


namespace BinaryNinja
{
	class BasicBlock;
	class FlowGraph;
	class Function;
	class LowLevelILFunction;
	class MediumLevelILFunction;
	class HighLevelILFunction;


	/*!
		\ingroup workflow
	*/
	class AnalysisContext :
	    public CoreRefCountObject<BNAnalysisContext, BNNewAnalysisContextReference, BNFreeAnalysisContext>
	{
		std::unique_ptr<Json::CharReader> m_reader;
		Json::StreamWriterBuilder m_builder;

	  public:
		AnalysisContext(BNAnalysisContext* analysisContext);
		virtual ~AnalysisContext();

		/*! Get the Function for the current AnalysisContext

			\return The function for the current context
		*/
		Ref<Function> GetFunction();

		/*! Get the low level IL function for the current AnalysisContext

			\return The LowLevelILFunction for the current context
		*/
		Ref<LowLevelILFunction> GetLowLevelILFunction();

		/*! Get the medium level IL function for the current AnalysisContext

			\return The MediumLevelILFunction for the current context
		*/
		Ref<MediumLevelILFunction> GetMediumLevelILFunction();

		/*! Get the high level IL function for the current AnalysisContext

			\return The HighLevelILFunction for the current context
		*/
		Ref<HighLevelILFunction> GetHighLevelILFunction();

		/*! Set a new BasicBlock list for the current analysis context

			\param basicBlocks The new list of BasicBlocks
		*/
		void SetBasicBlockList(std::vector<Ref<BasicBlock>> basicBlocks);

		/*! Set new lifted IL for the current analysis context

			\param liftedIL The new lifted IL
		*/
		void SetLiftedILFunction(Ref<LowLevelILFunction> liftedIL);

		/*! Set the new Low Level IL for the current analysis context

			\param lowLevelIL the new Low Level IL
		*/
		void SetLowLevelILFunction(Ref<LowLevelILFunction> lowLevelIL);

		/*! Set the new Medium Level IL for the current analysis context

			\param mediumLevelIL the new Medium Level IL
		*/
		void SetMediumLevelILFunction(Ref<MediumLevelILFunction> mediumLevelIL);

		/*! Set the new High Level IL for the current analysis context

			\param highLevelIL the new High Level IL
		*/
		void SetHighLevelILFunction(Ref<HighLevelILFunction> highLevelIL);

		bool Inform(const std::string& request);

#if ((__cplusplus >= 201403L) || (_MSVC_LANG >= 201703L))
	template <class... Ts>
	struct overload : Ts...
	{
		using Ts::operator()...;
	};
	template <class... Ts>
	overload(Ts...) -> overload<Ts...>;
#endif

#if ((__cplusplus >= 201403L) || (_MSVC_LANG >= 201703L))
		template <typename... Args>
		bool Inform(Args... args)
		{
			// using T = std::variant<Args...>; // FIXME: remove type duplicates
			using T = std::variant<std::string, const char*, uint64_t, Ref<Architecture>>;
			std::vector<T> unpackedArgs {args...};
			Json::Value request(Json::arrayValue);
			for (auto& arg : unpackedArgs)
				std::visit(overload {[&](Ref<Architecture> arch) { request.append(Json::Value(arch->GetName())); },
				               [&](uint64_t val) { request.append(Json::Value(val)); },
				               [&](auto& val) {
					               request.append(Json::Value(std::forward<decltype(val)>(val)));
				               }},
				    arg);

			return Inform(Json::writeString(m_builder, request));
		}
#endif
	};

	/*!
		\ingroup workflow
	*/
	class Activity : public CoreRefCountObject<BNActivity, BNNewActivityReference, BNFreeActivity>
	{
	  protected:
		std::function<void(Ref<AnalysisContext> analysisContext)> m_action;

		static void Run(void* ctxt, BNAnalysisContext* analysisContext);

	  public:
		/*!

			\code{.cpp}
		    MyClass::MyActionMethod(Ref<AnalysisContext> ac);
		    ...
		 	// Create a clone of the default workflow named "core.function.myWorkflowName"
		    Ref<Workflow> wf = BinaryNinja::Workflow::Instance()->Clone("core.function.myWorkflowName");
		 	wf->RegisterActivity(new BinaryNinja::Activity("core.function.myWorkflowName.resolveMethodCalls", &MyClass::MyActionMethod));
		 	\endcode

			\param configuration a JSON representation of the activity configuration
			\param action Workflow action, a function taking a Ref<AnalysisContext> as an argument.
		*/
		Activity(const std::string& configuration, const std::function<void(Ref<AnalysisContext>)>& action);
		Activity(BNActivity* activity);
		virtual ~Activity();

		/*! Get the Activity name

			\return Activity name
		*/
		std::string GetName() const;
	};

	/*! A Binary Ninja Workflow is an abstraction of a computational binary analysis pipeline and it provides the extensibility
		mechanism needed for tailored binary analysis and decompilation. More specifically, a Workflow is a repository of activities along with a
		unique strategy to execute them. Binary Ninja provides two Workflows named ``core.module.defaultAnalysis`` and ``core.function.defaultAnalysis``
		which expose the core analysis.

		A Workflow starts in the unregistered state from either creating a new empty Workflow, or cloning an existing Workflow. While unregistered
		it's possible to add and remove activities, as well as change the execution strategy. In order to use the Workflow on a binary it must be
		registered. Once registered the Workflow is immutable and available for use.

	 	\ingroup workflow
	*/
	class Workflow : public CoreRefCountObject<BNWorkflow, BNNewWorkflowReference, BNFreeWorkflow>
	{
	  public:
		Workflow(const std::string& name = "");
		Workflow(BNWorkflow* workflow);
		virtual ~Workflow() {}

		/*! Get a list of all workflows

			\return A list of Workflows
		*/
		static std::vector<Ref<Workflow>> GetList();

		/*! Get an instance of a workflow by name. If it is already registered, this will return the registered Workflow.
			If not, it will create and return a new Workflow.

			\param name Workflow name
			\return The registered workflow.
		*/
		static Ref<Workflow> Instance(const std::string& name = "");
		/*! Register a workflow, making it immutable and available for use

			\param workflow The workflow to register
			\param description A JSON description of the Workflow
			\return true on success, false otherwise
		*/
		static bool RegisterWorkflow(Ref<Workflow> workflow, const std::string& description = "");

		/*! Clone a workflow, copying all Activities and the execution strategy

			\param name Name for the new Workflow
			\param activity If specified, perform the clone with `activity` as the root
			\return A new Workflow
		*/
		Ref<Workflow> Clone(const std::string& name, const std::string& activity = "");

		/*! Register an Activity with this Workflow

			\param activity The Activity to register
			\param description A JSON description of the Activity
			\return
		*/

		/*! Register an Activity with this Workflow

			\param configuration a JSON representation of the activity configuration
			\param action Workflow action, a function taking a Ref<AnalysisContext> as an argument.
			\param subactivities The list of Activities to assign
			\return
		*/
		Ref<Activity> RegisterActivity(const std::string& configuration, const std::function<void(Ref<AnalysisContext>)>& action, const std::vector<std::string>& subactivities = {});

		/*! Register an Activity with this Workflow

			\param activity The Activity to register
			\param subactivities The list of Activities to assign
			\return
		*/
		Ref<Activity> RegisterActivity(Ref<Activity> activity, const std::vector<std::string>& subactivities = {});

		/*! Determine if an Activity exists in this Workflow

			\param activity The Activity name
			\return Whether the Activity exists in this workflow
		*/
		bool Contains(const std::string& activity);

		/*! Retrieve the configuration as an adjacency list in JSON for the Workflow,
			or if specified just for the given ``activity``.

			\param activity If specified, return the configuration for the ``activity``
			\return An adjacency list representation of the configuration in JSON
		*/
		std::string GetConfiguration(const std::string& activity = "");

		/*! Get the workflow name

			\return The workflow name
		*/
		std::string GetName() const;

		/*! Check whether the workflow is registered

			\return Whether the workflow is registered
		*/
		bool IsRegistered() const;

		/*! Get the amount of registered activities for this Workflow

			\return The amount of registered workflows
		*/
		size_t Size() const;

		/*! Retrieve an activity by name

			\param activity The Activity name
			\return The Activity object
		*/
		Ref<Activity> GetActivity(const std::string& activity);

		/*! Retrieve the list of activity roots for the Workflow, or if specified just for the given `activity`.

			\param activity If specified, return the roots for `activity`
			\return A list of root activity names.
		*/
		std::vector<std::string> GetActivityRoots(const std::string& activity = "");

		/*! Retrieve the list of all activities, or optionally a filtered list.

			\param activity If specified, return the direct children and optionally the descendants of the `activity` (includes `activity`)
			\param immediate whether to include only direct children of `activity` or all descendants
			\return A list of Activity names
		*/
		std::vector<std::string> GetSubactivities(const std::string& activity = "", bool immediate = true);

		/*! Assign the list of `activities` as the new set of children for the specified `activity`.

			\param activity The activity node to assign children
			\param subactivities the list of Activities to assign
			\return true on success, false otherwise
		*/
		bool AssignSubactivities(const std::string& activity, const std::vector<std::string>& subactivities = {});

		/*! Remove all activity nodes from this Workflow

			\return true on success, false otherwise
		*/
		bool Clear();

		/*! Insert an activity before the specified activity and at the same level.

			\param activity Name of the activity to insert the new one before
			\param newActivity Name of the new activity to be inserted
			\return true on success, false otherwise
		*/
		bool Insert(const std::string& activity, const std::string& newActivity);

		/*! Insert a list of activities before the specified activity and at the same level.

			\param activity Name of the activity to insert the new one before
			\param newActivity Name of the new activities to be inserted
			\return true on success, false otherwise
		*/
		bool Insert(const std::string& activity, const std::vector<std::string>& activities);

		/*! Remove an activity by name

			\param activity Name of the activity to remove
			\return true on success, false otherwise
		*/
		bool Remove(const std::string& activity);

		/*! Replace the activity name

			\param activity Name of the activity to replace
			\param newActivity Name of the new activity
			\return true on success, false otherwise
		*/
		bool Replace(const std::string& activity, const std::string& newActivity);

		/*! Generate a FlowGraph object for the current Workflow

			\param activity if specified, generate the Flowgraph using ``activity`` as the root
			\param sequential whether to generate a **Composite** or **Sequential** style graph
			\return FlowGraph on success
		*/
		Ref<FlowGraph> GetGraph(const std::string& activity = "", bool sequential = false);
		void ShowReport(const std::string& name);
	};

}
