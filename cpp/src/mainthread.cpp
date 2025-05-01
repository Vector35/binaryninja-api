#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


struct MainThreadActionContext
{
	function<void()> action;
	exception_ptr exception;
};


MainThreadAction::MainThreadAction(BNMainThreadAction* action)
{
	m_object = action;
}


void MainThreadAction::Execute()
{
	BNExecuteMainThreadAction(m_object);
}


bool MainThreadAction::IsDone() const
{
	return BNIsMainThreadActionDone(m_object);
}


void MainThreadAction::Wait()
{
	BNWaitForMainThreadAction(m_object);
}


static void AddMainThreadAction(void* ctxt, BNMainThreadAction* action)
{
	MainThreadActionHandler* handler = (MainThreadActionHandler*)ctxt;
	handler->AddMainThreadAction(new MainThreadAction(action));
}


void BinaryNinja::RegisterMainThread(MainThreadActionHandler* handler)
{
	BNMainThreadCallbacks cb;
	cb.context = handler;
	cb.addAction = AddMainThreadAction;
	BNRegisterMainThread(&cb);
}


static void ExecuteAction(void* ctxt)
{
	MainThreadActionContext* action = (MainThreadActionContext*)ctxt;

	// We can't throw across a thread and *certainly* not across the api boundary
	// But how do we deal with exceptions thrown in main thread callbacks if the caller doesn't wait for them?
	// Likely the only good solution is abort()
	try
	{
		action->action();
	}
	catch (const std::exception& e)
	{
		LogError("Exception in main thread handler: %s", e.what());
		fprintf(stderr, "Exception in main thread handler: %s\n", e.what());
		abort();
	}
	catch (...)
	{
		LogError("Exception in main thread handler: <unknown exception>");
		fprintf(stderr, "Exception in main thread handler: <unknown exception>\n");
		abort();
	}
	delete action;
}


Ref<MainThreadAction> BinaryNinja::ExecuteOnMainThread(const function<void()>& action)
{
	MainThreadActionContext* ctxt = new MainThreadActionContext;
	ctxt->action = action;
	BNMainThreadAction* obj = BNExecuteOnMainThread(ctxt, ExecuteAction);
	return obj ? new MainThreadAction(obj) : nullptr;
}


static void ExecuteActionLocal(void* ctxt)
{
	MainThreadActionContext* action = (MainThreadActionContext*)ctxt;
	try
	{
		action->action();
	}
	catch (...)
	{
		action->exception = current_exception();
	}
}


void BinaryNinja::ExecuteOnMainThreadAndWait(const function<void()>& action)
{
	MainThreadActionContext ctxt;
	ctxt.action = action;
	ctxt.exception = exception_ptr();
	BNExecuteOnMainThreadAndWait(&ctxt, ExecuteActionLocal);
	if (ctxt.exception)
	{
		rethrow_exception(ctxt.exception);
	}
}


bool BinaryNinja::IsMainThread()
{
	return BNIsMainThread();
}
