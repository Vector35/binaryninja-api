#pragma once
#include "mainthread.h"
#include "refcount.hpp"
#include "log.hpp"

namespace BinaryNinja {

	class MainThreadAction :
	    public CoreRefCountObject<BNMainThreadAction, BNNewMainThreadActionReference, BNFreeMainThreadAction>
	{
	  public:
		MainThreadAction(BNMainThreadAction* action);
		void Execute();
		bool IsDone() const;
		void Wait();
	};

	class MainThreadActionHandler
	{
	  public:
		virtual void AddMainThreadAction(MainThreadAction* action) = 0;
	};

	void RegisterMainThread(MainThreadActionHandler* handler);
	Ref<MainThreadAction> ExecuteOnMainThread(const std::function<void()>& action);
	void ExecuteOnMainThreadAndWait(const std::function<void()>& action);
	bool IsMainThread();
}