#pragma once

#include "refcount.h"
#include <functional>
#include <string>

namespace BinaryNinja
{
	class MainThreadAction;
	class MainThreadActionHandler;

	/*!
		\ingroup mainthread
	*/
	void RegisterMainThread(MainThreadActionHandler* handler);

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	Ref<MainThreadAction> ExecuteOnMainThread(const std::function<void()>& action);

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	void ExecuteOnMainThreadAndWait(const std::function<void()>& action);

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	bool IsMainThread();

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	void WorkerEnqueue(const std::function<void()>& action, const std::string& name = "");

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	void WorkerEnqueue(RefCountObject* owner, const std::function<void()>& action, const std::string& name = "");

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	void WorkerPriorityEnqueue(const std::function<void()>& action, const std::string& name = "");

	/*!
		\ingroup mainthread
	*/
	void WorkerPriorityEnqueue(RefCountObject* owner, const std::function<void()>& action, const std::string& name = "");

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	void WorkerInteractiveEnqueue(const std::function<void()>& action, const std::string& name = "");

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	void WorkerInteractiveEnqueue(RefCountObject* owner, const std::function<void()>& action, const std::string& name = "");

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	size_t GetWorkerThreadCount();

	/*!
		@threadsafe
		\ingroup mainthread
	*/
	void SetWorkerThreadCount(size_t count);

}
