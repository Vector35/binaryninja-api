#include "binaryninjaapi.h"
#include <string>

using namespace BinaryNinja;
using namespace std;


Activity::Activity(const string& configuration, const std::function<void(Ref<AnalysisContext> analysisContext)>& action,
	const std::function<bool(Ref<Activity>, Ref<AnalysisContext>)>& eligibility) : m_action(action), m_eligibility(eligibility)
{
	// LogError("API-Side Activity Constructed!");
	if (eligibility)
		m_object = BNCreateActivityWithEligibility(configuration.c_str(), this, RunAction, CheckEligibility);
	else
		m_object = BNCreateActivity(configuration.c_str(), this, RunAction);
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


void Activity::RunAction(void* ctxt, BNAnalysisContext* analysisContext)
{
	// LogError("API-Side Activity RunAction!");
	auto boundActivity = static_cast<Activity*>(ctxt);
	Ref<AnalysisContext> ac = new AnalysisContext(BNNewAnalysisContextReference(analysisContext));
	boundActivity->m_action(ac);
}


bool Activity::CheckEligibility(void* ctxt, BNActivity* activity, BNAnalysisContext* analysisContext)
{
	auto boundActivity = static_cast<Activity*>(ctxt);
	Ref<Activity> act = new Activity(BNNewActivityReference(activity));
	Ref<AnalysisContext> ac = new AnalysisContext(BNNewAnalysisContextReference(analysisContext));
	return boundActivity->m_eligibility(act, ac);
}


string Activity::GetName() const
{
	// LogError("API-Side Activity GetName!");
	char* name = BNActivityGetName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}
