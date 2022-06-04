#include "json/json.h"
#include "flowgraph.hpp"
#include "workflow.hpp"
#include "activity.hpp"
#include <string>
#include <variant>

using namespace BinaryNinja;
using namespace std;


Workflow::Workflow(const string& name)
{
	m_object = BNCreateWorkflow(name.c_str());
}


Workflow::Workflow(BNWorkflow* workflow)
{
	m_object = BNNewWorkflowReference(workflow);
}


vector<Ref<Workflow>> Workflow::GetList()
{
	size_t count;
	BNWorkflow** list = BNGetWorkflowList(&count);

	vector<Ref<Workflow>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Workflow(BNNewWorkflowReference(list[i])));

	BNFreeWorkflowList(list, count);
	return result;
}


Ref<Workflow> Workflow::Instance(const string& name)
{
	return new Workflow(BNWorkflowInstance(name.c_str()));
}


bool Workflow::RegisterWorkflow(Ref<Workflow> workflow, const string& description)
{
	return BNRegisterWorkflow(workflow->m_object, description.c_str());
}


Ref<Workflow> Workflow::Clone(const string& name, const string& activity)
{
	return new Workflow(BNWorkflowClone(m_object, name.c_str(), activity.c_str()));
}


bool Workflow::RegisterActivity(Ref<Activity> activity, const string& description)
{
	return RegisterActivity(activity, {}, description);
}


bool Workflow::RegisterActivity(Ref<Activity> activity, const vector<string>& subactivities, const string& description)
{
	activity->AddRefForRegistration();  // TODO

	char** buffer = new char*[subactivities.size()];
	if (!buffer)
		return false;

	for (size_t i = 0; i < subactivities.size(); i++)
		buffer[i] = BNAllocString(subactivities[i].c_str());

	bool result = BNWorkflowRegisterActivity(
	    m_object, activity->GetObject(), (const char**)buffer, subactivities.size(), description.c_str());

	for (size_t i = 0; i < subactivities.size(); i++)
		BNFreeString(buffer[i]);
	delete[] buffer;
	return result;
}


bool Workflow::Contains(const string& activity)
{
	return BNWorkflowContains(m_object, activity.c_str());
}


string Workflow::GetConfiguration(const string& activity)
{
	char* tmpStr = BNWorkflowGetConfiguration(m_object, activity.c_str());
	string result(tmpStr);
	BNFreeString(tmpStr);
	return result;
}


string Workflow::GetName() const
{
	char* str = BNGetWorkflowName(m_object);
	string result = str;
	BNFreeString(str);
	return result;
}


bool Workflow::IsRegistered() const
{
	return BNWorkflowIsRegistered(m_object);
}


size_t Workflow::Size() const
{
	return BNWorkflowSize(m_object);
}


Ref<Activity> Workflow::GetActivity(const string& activity)
{
	BNActivity* activityObject = BNWorkflowGetActivity(m_object, activity.c_str());
	return new Activity(BNNewActivityReference(activityObject));
}


vector<string> Workflow::GetActivityRoots(const string& activity)
{
	size_t size = 0;
	char** outBuffer = (char**)BNWorkflowGetActivityRoots(m_object, activity.c_str(), &size);

	vector<string> result;
	result.reserve(size);
	for (size_t i = 0; i < size; i++)
		result.emplace_back(outBuffer[i]);

	BNFreeStringList(outBuffer, size);
	return result;
}


vector<string> Workflow::GetSubactivities(const string& activity, bool immediate)
{
	size_t size = 0;
	char** outBuffer = (char**)BNWorkflowGetSubactivities(m_object, activity.c_str(), immediate, &size);

	vector<string> result;
	result.reserve(size);
	for (size_t i = 0; i < size; i++)
		result.emplace_back(outBuffer[i]);

	BNFreeStringList(outBuffer, size);
	return result;
}


bool Workflow::AssignSubactivities(const string& activity, const vector<string>& subactivities)
{
	char** buffer = new char*[subactivities.size()];
	if (!buffer)
		return false;

	for (size_t i = 0; i < subactivities.size(); i++)
		buffer[i] = BNAllocString(subactivities[i].c_str());

	bool result = BNWorkflowAssignSubactivities(m_object, activity.c_str(), (const char**)buffer, subactivities.size());

	for (size_t i = 0; i < subactivities.size(); i++)
		BNFreeString(buffer[i]);
	delete[] buffer;
	return result;
}


bool Workflow::Clear()
{
	return BNWorkflowClear(m_object);
}


bool Workflow::Insert(const string& activity, const std::string& newActivity)
{
	char* buffer[1];
	buffer[0] = BNAllocString(newActivity.c_str());

	bool result = BNWorkflowInsert(m_object, activity.c_str(), (const char**)buffer, 1);
	BNFreeString(buffer[0]);
	return result;
}


bool Workflow::Insert(const string& activity, const vector<string>& activities)
{
	char** buffer = new char*[activities.size()];
	if (!buffer)
		return false;

	for (size_t i = 0; i < activities.size(); i++)
		buffer[i] = BNAllocString(activities[i].c_str());

	bool result = BNWorkflowInsert(m_object, activity.c_str(), (const char**)buffer, activities.size());

	for (size_t i = 0; i < activities.size(); i++)
		BNFreeString(buffer[i]);
	delete[] buffer;
	return result;
}


bool Workflow::Remove(const string& activity)
{
	return BNWorkflowRemove(m_object, activity.c_str());
}


bool Workflow::Replace(const string& activity, const string& newActivity)
{
	return BNWorkflowReplace(m_object, activity.c_str(), newActivity.c_str());
}


Ref<FlowGraph> Workflow::GetGraph(const string& activity, bool sequential)
{
	BNFlowGraph* graph = BNWorkflowGetGraph(m_object, activity.c_str(), sequential);
	if (!graph)
		return nullptr;
	return new CoreFlowGraph(graph);
}


void Workflow::ShowReport(const std::string& name)
{
	BNWorkflowShowReport(m_object, name.c_str());
}


// bool Workflow::Run(const string& activity, Ref<AnalysisContext> analysisContext)
// {

// }
