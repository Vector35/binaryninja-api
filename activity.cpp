#include "binaryninjaapi.h"
#include <string>

using namespace BinaryNinja;
using namespace std;


Activity::Activity(const string& configuration, const std::function<void(Ref<AnalysisContext> analysisContext)>& action) : m_action(action)
{
	// LogError("API-Side Activity Constructed!");
	m_object = BNCreateActivity(configuration.c_str(), this, Run);
}


Activity::Activity(BNActivity* activity)
{
	// LogError("API-Side Activity Constructed!");
	m_object = BNNewActivityReference(activity);
}


Activity::~Activity()
{
	// LogError("API-Side Activity Destructed!");
}


void Activity::Run(void* ctxt, BNAnalysisContext* analysisContext)
{
	// LogError("API-Side Activity Run!");
	Activity* activity = (Activity*)ctxt;
	Ref<AnalysisContext> ac = new AnalysisContext(BNNewAnalysisContextReference(analysisContext));
	activity->m_action(ac);
}


string Activity::GetName() const
{
	// LogError("API-Side Activity GetName!");
	char* name = BNActivityGetName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}
