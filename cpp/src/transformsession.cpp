#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


TransformSession::TransformSession(const string& filename, const string& options)
{
	m_object = BNCreateTransformSession(filename.c_str(), options.c_str());
}


TransformSession::TransformSession(const string& filename, BNTransformSessionMode mode, const string& options)
{
	m_object = BNCreateTransformSessionWithMode(filename.c_str(), mode, options.c_str());
}


TransformSession::TransformSession(Ref<BinaryView> initialView, const string& options)
{
	m_object = BNCreateTransformSessionFromBinaryView(initialView->GetObject(), options.c_str());
}


TransformSession::TransformSession(Ref<BinaryView> initialView, BNTransformSessionMode mode, const string& options)
{
	m_object = BNCreateTransformSessionFromBinaryViewWithMode(initialView->GetObject(), mode, options.c_str());
}


TransformSession::TransformSession(Ref<TransformContext> context, BNTransformSessionMode mode, const string& options)
{
	m_object = BNCreateTransformSessionFromTransformContextWithMode(context->GetObject(), mode, options.c_str());
}


TransformSession::TransformSession(BNTransformSession* session)
{
	m_object = session;
}


TransformSession::~TransformSession()
{
}


void TransformSession::SetInteractive(bool interactive)
{
	BNTransformSessionSetInteractive(m_object, interactive);
}


Ref<BinaryView> TransformSession::GetCurrentView() const
{
	BNBinaryView* view = BNTransformSessionGetCurrentView(m_object);
	if (!view)
		return nullptr;
	return new BinaryView(view);
}


Ref<TransformContext> TransformSession::GetRootContext() const
{
	BNTransformContext* context = BNTransformSessionGetRootContext(m_object);
	if (!context)
		return nullptr;
	return new TransformContext(context);
}


Ref<TransformContext> TransformSession::GetCurrentContext() const
{
	BNTransformContext* context = BNTransformSessionGetCurrentContext(m_object);
	if (!context)
		return nullptr;
	return new TransformContext(context);
}


bool TransformSession::ProcessFrom(Ref<TransformContext> context)
{
	return BNTransformSessionProcessFrom(m_object, context->GetObject());
}


bool TransformSession::Process()
{
	return BNTransformSessionProcess(m_object);
}


bool TransformSession::HasAnyStages() const
{
	return BNTransformSessionHasAnyStages(m_object);
}


bool TransformSession::HasSinglePath() const
{
	return BNTransformSessionHasSinglePath(m_object);
}


vector<Ref<TransformContext>> TransformSession::GetSelectedContexts() const
{
	size_t count;
	BNTransformContext** contexts = BNTransformSessionGetSelectedContexts(m_object, &count);
	vector<Ref<TransformContext>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new TransformContext(BNNewTransformContextReference(contexts[i])));

	BNFreeTransformContextList(contexts, count);
	return result;
}


void TransformSession::SetSelectedContexts(const vector<Ref<TransformContext>>& contexts)
{
	BNTransformContext** cContexts = new BNTransformContext*[contexts.size()];
	for (size_t i = 0; i < contexts.size(); i++)
		cContexts[i] = contexts[i]->GetObject();

	BNTransformSessionSetSelectedContexts(m_object, cContexts, contexts.size());
	delete[] cContexts;
}
