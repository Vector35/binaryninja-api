#include "binaryninjaapi.h"
#include "activity.h"
#include <string>
#include <typeinfo>
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


#if ((__cplusplus >= 201403L) || (_MSVC_LANG >= 201703L))
template <class... Ts>
struct overload : Ts...
{
	using Ts::operator()...;
};
template <class... Ts>
overload(Ts...) -> overload<Ts...>;

template <typename... Args>
bool AnalysisContext::Inform(Args... args)
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

Activity::Activity(const string& name, const std::function<void(Ref<AnalysisContext> analysisContext)>& action) :
    m_action(action)
{
	// LogError("API-Side Activity Constructed!");
	m_object = BNCreateActivity(name.c_str(), this, Run);
}


Activity::Activity(BNActivity* activity)
{
	m_object = BNNewActivityReference(activity);
}


Activity::~Activity()
{
	// LogError("API-Side Activity Destructed!");
}


void Activity::Run(void* ctxt, BNAnalysisContext* analysisContext)
{
	Activity* activity = (Activity*)ctxt;
	Ref<AnalysisContext> ac = new AnalysisContext(BNNewAnalysisContextReference(analysisContext));
	activity->m_action(ac);
}


string Activity::GetName() const
{
	char* name = BNActivityGetName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}
