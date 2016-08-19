#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


struct MainThreadActionContext
{
	function<void()> action;
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
	action->action();
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
	action->action();
}


void BinaryNinja::ExecuteOnMainThreadAndWait(const function<void()>& action)
{
	MainThreadActionContext ctxt;
	ctxt.action = action;
	BNExecuteOnMainThreadAndWait(&ctxt, ExecuteActionLocal);
}
