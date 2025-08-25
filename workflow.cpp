#include "binaryninjaapi.h"
#include "rapidjsonwrapper.h"
#include <string>
#include <variant>

using namespace BinaryNinja;
using namespace std;


AnalysisContext::AnalysisContext(BNAnalysisContext* analysisContext)
{
	// LogError("API-Side AnalysisContext Constructed!");
	m_object = analysisContext;
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


Ref<LowLevelILFunction> AnalysisContext::GetLiftedILFunction()
{
	BNLowLevelILFunction* func = BNAnalysisContextGetLiftedILFunction(m_object);
	if (!func)
		return nullptr;
	return new LowLevelILFunction(func);
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


void AnalysisContext::SetMediumLevelILFunction(
	Ref<MediumLevelILFunction> mediumLevelIL,
	std::unordered_map<size_t /* llil ssa */, size_t /* mlil */> llilSsaToMlilInstrMap,
	std::vector<BNExprMapInfo> llilSsaToMlilExprMap
)
{
	if (llilSsaToMlilExprMap.empty() || llilSsaToMlilInstrMap.empty())
	{
		// Build up maps from existing data in the function
		llilSsaToMlilExprMap = mediumLevelIL->GetLLILSSAToMLILExprMap(true);
		llilSsaToMlilInstrMap = mediumLevelIL->GetLLILSSAToMLILInstrMap(true);
	}

	std::vector<size_t> instrMapVec;
	// Technically imprecise but doesn't matter this is just reserving
	instrMapVec.reserve(llilSsaToMlilInstrMap.size());
	for (auto& [llilSSAIndex, mlilIndex]: llilSsaToMlilInstrMap)
	{
		if (instrMapVec.size() <= llilSSAIndex)
		{
			instrMapVec.resize(llilSSAIndex + 1, BN_INVALID_EXPR);
		}
		instrMapVec[llilSSAIndex] = mlilIndex;
	}

	BNSetMediumLevelILFunction(
		m_object,
		mediumLevelIL->m_object,
		instrMapVec.data(),
		instrMapVec.size(),
		llilSsaToMlilExprMap.data(),
		llilSsaToMlilExprMap.size()
	);
}


void AnalysisContext::SetHighLevelILFunction(Ref<HighLevelILFunction> highLevelIL)
{
	BNSetHighLevelILFunction(m_object, highLevelIL->m_object);
}


bool AnalysisContext::Inform(const char* request)
{
	return BNAnalysisContextInform(m_object, request);
}


bool AnalysisContext::Inform(const string& request)
{
	return BNAnalysisContextInform(m_object, request.c_str());
}


bool WorkflowMachine::PostRequest(const std::string& command)
{
	rapidjson::Document request(rapidjson::kObjectType);
	rapidjson::Document::AllocatorType& allocator = request.GetAllocator();
	rapidjson::Value commandValue(command.c_str(), command.size(), allocator);
	request.AddMember("command", commandValue, allocator);
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


WorkflowMachine::WorkflowMachine(Ref<BinaryView> view): m_view(view)
{

}


WorkflowMachine::WorkflowMachine(Ref<Function> function): m_function(function)
{

}


bool WorkflowMachine::PostJsonRequest(const std::string& request)
{
	string jsonResult;
	if (m_function)
		jsonResult = BNPostWorkflowRequestForFunction(m_function->GetObject(), request.c_str());
	else
		jsonResult = BNPostWorkflowRequestForBinaryView(m_view->GetObject(), request.c_str());

	rapidjson::Document response(rapidjson::kObjectType);
	response.Parse(jsonResult.c_str());
	if (response.HasMember("commandStatus") && response["commandStatus"].HasMember("accepted"))
		return response["commandStatus"]["accepted"].GetBool();

	return false;
}


Ref<FlowGraph> WorkflowMachine::GetGraph(const std::string& activity, bool sequential)
{
	BNFlowGraph* graph;
	if (m_function)
		graph = BNGetWorkflowGraphForFunction(m_function->GetObject(), activity.c_str(), sequential);
	else
		graph = BNGetWorkflowGraphForBinaryView(m_view->GetObject(), activity.c_str(), sequential);

	return new CoreFlowGraph(graph);
}


void WorkflowMachine::ShowTopology()
{
	if (m_function)
		BNShowWorkflowReportForFunction(m_function->GetObject(), "topology");
	else
		BNShowWorkflowReportForBinaryView(m_view->GetObject(), "topology");
}


WorkflowMachine::Status WorkflowMachine::GetStatus()
{
	WorkflowMachine::Status status;
	rapidjson::Document request(rapidjson::kObjectType);
	rapidjson::Document::AllocatorType& allocator = request.GetAllocator();
	request.AddMember("command", "status", allocator);
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
	if (response.HasMember("machineState") && response["machineState"].HasMember("state") && response["machineState"].HasMember("activity"))
	{
		status.state = response["machineState"]["state"].GetString();
		status.activity = response["machineState"]["activity"].GetString();
	}
	if (response.HasMember("logStatus") && response["logStatus"].HasMember("local") && response["logStatus"].HasMember("global"))
	{
		status.localLogEnabled = response["logStatus"]["local"].GetBool();
		status.globalLogEnabled = response["logStatus"]["global"].GetBool();
	}

	return status;
}


bool WorkflowMachine::Resume()
{
	return PostRequest("resume");
}


bool WorkflowMachine::Run()
{
	return PostRequest("run");
}


bool WorkflowMachine::Configure()
{
	return PostRequest("configure");
}


bool WorkflowMachine::Halt()
{
	return PostRequest("halt");
}


bool WorkflowMachine::Reset()
{
	return PostRequest("reset");
}


bool WorkflowMachine::Enable()
{
	return PostRequest("enable");
}


bool WorkflowMachine::Disable()
{
	return PostRequest("disable");
}


bool WorkflowMachine::Step()
{
	return PostRequest("step");
}


bool WorkflowMachine::SetLogEnabled(bool enable, bool global)
{
	rapidjson::Document request(rapidjson::kObjectType);
	rapidjson::Document::AllocatorType& allocator = request.GetAllocator();
	request.AddMember("command", "log", allocator);
	request.AddMember("enable", enable, allocator);
	request.AddMember("global", global, allocator);
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


std::optional<bool> WorkflowMachine::QueryOverride(const string& activity)
{
	rapidjson::Document request(rapidjson::kObjectType);
	rapidjson::Document::AllocatorType& allocator = request.GetAllocator();
	request.AddMember("command", "override", allocator);
	request.AddMember("action", "query", allocator);
	request.AddMember("activity", activity, allocator);
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
	request.AddMember("activity", activity, allocator);
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
	request.AddMember("activity", activity, allocator);
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
	m_object = workflow;
}


Workflow::Workflow(BNWorkflow* workflow, Ref<BinaryView> view)
{
	m_object = workflow;
	m_machine = make_unique<WorkflowMachine>(view);
}


Workflow::Workflow(BNWorkflow* workflow, Ref<Function> function)
{
	m_object = workflow;
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


Ref<Workflow> Workflow::Get(const string& name)
{
	auto result = BNWorkflowGet(name.c_str());
	if (!result)
		return nullptr;

	return new Workflow(result);
}


Ref<Workflow> Workflow::GetOrCreate(const string& name)
{
	return new Workflow(BNWorkflowGetOrCreate(name.c_str()));
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


bool Workflow::InsertAfter(const string& activity, const string& newActivity)
{
	char* buffer[1];
	buffer[0] = BNAllocString(newActivity.c_str());

	bool result = BNWorkflowInsertAfter(m_object, activity.c_str(), (const char**)buffer, 1);
	BNFreeString(buffer[0]);
	return result;
}


bool Workflow::InsertAfter(const string& activity, const vector<string>& activities)
{
	char** buffer = new char*[activities.size()];
	if (!buffer)
		return false;

	for (size_t i = 0; i < activities.size(); i++)
		buffer[i] = BNAllocString(activities[i].c_str());

	bool result = BNWorkflowInsertAfter(m_object, activity.c_str(), (const char**)buffer, activities.size());

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
