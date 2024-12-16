#include "binaryninjaapi.h"
#include "json/json.h"
#include "rapidjsonwrapper.h"
#include <string>
#include <variant>

using namespace BinaryNinja;
using namespace std;


AnalysisContext::AnalysisContext(BNAnalysisContext* analysisContext) :
    m_reader(Json::CharReaderBuilder().newCharReader())
{
	// LogError("API-Side AnalysisContext Constructed!");
	m_object = analysisContext;
	m_builder["indentation"] = "";
}


AnalysisContext::~AnalysisContext()
{
	// LogError("API-Side AnalysisContext Destructed!");
}


Ref<BinaryView> AnalysisContext::GetBinaryView()
{
	BNBinaryView* view = BNAnalysisContextGetBinaryView(m_object);
	if (!view)
		return nullptr;
	return new BinaryView(view);
}


Ref<Function> AnalysisContext::GetFunction()
{
	BNFunction* func = BNAnalysisContextGetFunction(m_object);
	if (!func)
		return nullptr;
	return new Function(func);
}


Ref<LowLevelILFunction> AnalysisContext::GetLowLevelILFunction()
{
	BNLowLevelILFunction* func = BNAnalysisContextGetLowLevelILFunction(m_object);
	if (!func)
		return nullptr;
	return new LowLevelILFunction(func);
}


Ref<MediumLevelILFunction> AnalysisContext::GetMediumLevelILFunction()
{
	BNMediumLevelILFunction* func = BNAnalysisContextGetMediumLevelILFunction(m_object);
	if (!func)
		return nullptr;
	return new MediumLevelILFunction(func);
}


Ref<HighLevelILFunction> AnalysisContext::GetHighLevelILFunction()
{
	BNHighLevelILFunction* func = BNAnalysisContextGetHighLevelILFunction(m_object);
	if (!func)
		return nullptr;
	return new HighLevelILFunction(func);
}


void AnalysisContext::SetBasicBlockList(vector<Ref<BasicBlock>> basicBlocks)
{
	BNBasicBlock** blocks = new BNBasicBlock*[basicBlocks.size()];
	size_t i = 0;
	for (auto& j : basicBlocks)
		blocks[i++] = j->GetObject();

	BNSetBasicBlockList(m_object, blocks, basicBlocks.size());
	delete[] blocks;
}


void AnalysisContext::SetLiftedILFunction(Ref<LowLevelILFunction> liftedIL)
{
	BNSetLiftedILFunction(m_object, liftedIL->m_object);
}


void AnalysisContext::SetLowLevelILFunction(Ref<LowLevelILFunction> lowLevelIL)
{
	BNSetLowLevelILFunction(m_object, lowLevelIL->m_object);
}


void AnalysisContext::SetMediumLevelILFunction(Ref<MediumLevelILFunction> mediumLevelIL)
{
	BNSetMediumLevelILFunction(m_object, mediumLevelIL->m_object);
}


void AnalysisContext::SetHighLevelILFunction(Ref<HighLevelILFunction> highLevelIL)
{
	BNSetHighLevelILFunction(m_object, highLevelIL->m_object);
}


bool AnalysisContext::Inform(const string& request)
{
	return BNAnalysisContextInform(m_object, request.c_str());
}


WorkflowMachine::WorkflowMachine(Ref<BinaryView> view): m_view(view)
{

}


WorkflowMachine::WorkflowMachine(Ref<Function> function): m_function(function)
{

}


std::optional<bool> WorkflowMachine::QueryOverride(const string& activity)
{
	rapidjson::Document request(rapidjson::kObjectType);
	rapidjson::Document::AllocatorType& allocator = request.GetAllocator();
	request.AddMember("command", "override", allocator);
	request.AddMember("action", "query", allocator);
	request.AddMember("activity", rapidjson::Value(activity.c_str(), allocator), allocator);
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	request.Accept(writer);

	string jsonResult;
	if (m_function)
		jsonResult = BNPostWorkflowRequestForFunction(m_function->GetObject(), buffer.GetString());
	else
		jsonResult = BNPostWorkflowRequestForBinaryView(m_view->GetObject(), buffer.GetString());

	rapidjson::Document response(rapidjson::kObjectType);
	response.Parse(jsonResult.c_str());
	if (response.HasMember("response") && response["response"].HasMember("activity") && response["response"]["activity"].HasMember("override"))
		return response["response"]["activity"]["override"].GetBool();

	return std::nullopt;
}


bool WorkflowMachine::SetOverride(const string& activity, bool enable)
{
	rapidjson::Document request(rapidjson::kObjectType);
	rapidjson::Document::AllocatorType& allocator = request.GetAllocator();
	request.AddMember("command", "override", allocator);
	request.AddMember("action", "set", allocator);
	request.AddMember("activity", rapidjson::Value(activity.c_str(), allocator), allocator);
	request.AddMember("enable", enable, allocator);
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	request.Accept(writer);

	string jsonResult;
	if (m_function)
		jsonResult = BNPostWorkflowRequestForFunction(m_function->GetObject(), buffer.GetString());
	else
		jsonResult = BNPostWorkflowRequestForBinaryView(m_view->GetObject(), buffer.GetString());

	rapidjson::Document response(rapidjson::kObjectType);
	response.Parse(jsonResult.c_str());
	if (response.HasMember("commandStatus") && response["commandStatus"].HasMember("accepted"))
		return response["commandStatus"]["accepted"].GetBool();

	return false;
}


bool WorkflowMachine::ClearOverride(const string& activity)
{
	rapidjson::Document request(rapidjson::kObjectType);
	rapidjson::Document::AllocatorType& allocator = request.GetAllocator();
	request.AddMember("command", "override", allocator);
	request.AddMember("action", "clear", allocator);
	request.AddMember("activity", rapidjson::Value(activity.c_str(), allocator), allocator);
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	request.Accept(writer);

	string jsonResult;
	if (m_function)
		jsonResult = BNPostWorkflowRequestForFunction(m_function->GetObject(), buffer.GetString());
	else
		jsonResult = BNPostWorkflowRequestForBinaryView(m_view->GetObject(), buffer.GetString());

	rapidjson::Document response(rapidjson::kObjectType);
	response.Parse(jsonResult.c_str());
	if (response.HasMember("commandStatus") && response["commandStatus"].HasMember("accepted"))
		return response["commandStatus"]["accepted"].GetBool();

	return false;
}


Workflow::Workflow(const string& name)
{
	m_object = BNCreateWorkflow(name.c_str());
}


Workflow::Workflow(BNWorkflow* workflow)
{
	m_object = BNNewWorkflowReference(workflow);
}


Workflow::Workflow(BNWorkflow* workflow, Ref<BinaryView> view)
{
	m_object = BNNewWorkflowReference(workflow);
	m_machine = make_unique<WorkflowMachine>(view);
}


Workflow::Workflow(BNWorkflow* workflow, Ref<Function> function)
{
	m_object = BNNewWorkflowReference(workflow);
	m_machine = make_unique<WorkflowMachine>(function);
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


bool Workflow::RegisterWorkflow(Ref<Workflow> workflow, const string& configuration)
{
	return BNRegisterWorkflow(workflow->m_object, configuration.c_str());
}


Ref<Workflow> Workflow::Clone(const string& name, const string& activity)
{
	return new Workflow(BNWorkflowClone(m_object, name.c_str(), activity.c_str()));
}


Ref<Activity> Workflow::RegisterActivity(const string& configuration, const function<void(Ref<AnalysisContext>)>& action, const vector<string>& subactivities)
{
	return RegisterActivity(new Activity(configuration, action), subactivities);
}


Ref<Activity> Workflow::RegisterActivity(Ref<Activity> activity, const vector<string>& subactivities)
{
	char** buffer = new char*[subactivities.size()];
	if (!buffer)
		return nullptr;

	activity->AddRefForRegistration(); // TODO
	for (size_t i = 0; i < subactivities.size(); i++)
		buffer[i] = BNAllocString(subactivities[i].c_str());

	BNActivity* activityObject = BNWorkflowRegisterActivity(m_object, activity->GetObject(), (const char**)buffer, subactivities.size());

	for (size_t i = 0; i < subactivities.size(); i++)
		BNFreeString(buffer[i]);
	delete[] buffer;

	if (!activityObject)
		return nullptr;

	return new Activity(BNNewActivityReference(activityObject));
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


bool Workflow::Insert(const string& activity, const string& newActivity)
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


void Workflow::ShowReport(const string& name)
{
	BNWorkflowShowReport(m_object, name.c_str());
}


vector<string> Workflow::GetEligibilitySettings()
{
	size_t size = 0;
	char** outBuffer = (char**)BNWorkflowGetEligibilitySettings(m_object, &size);

	vector<string> result;
	result.reserve(size);
	for (size_t i = 0; i < size; i++)
		result.emplace_back(outBuffer[i]);

	BNFreeStringList(outBuffer, size);
	return result;
}
