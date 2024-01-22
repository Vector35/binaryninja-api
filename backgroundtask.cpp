#include "binaryninjaapi.h"

using namespace std;
using namespace BinaryNinja;


BackgroundTask::BackgroundTask(BNBackgroundTask* task)
{
	m_object = task;
}


BackgroundTask::BackgroundTask(const string& initialText, bool canCancel)
{
	m_object = BNBeginBackgroundTask(initialText.c_str(), canCancel);
}


bool BackgroundTask::CanCancel() const
{
	return BNCanCancelBackgroundTask(m_object);
}


bool BackgroundTask::IsCancelled() const
{
	return BNIsBackgroundTaskCancelled(m_object);
}


bool BackgroundTask::IsFinished() const
{
	return BNIsBackgroundTaskFinished(m_object);
}


string BackgroundTask::GetProgressText() const
{
	char* text = BNGetBackgroundTaskProgressText(m_object);
	string result = text;
	BNFreeString(text);
	return result;
}


uint64_t BackgroundTask::GetRuntimeSeconds() const
{
	return BNGetBackgroundTaskRuntimeSeconds(m_object);
}


void BackgroundTask::Cancel()
{
	BNCancelBackgroundTask(m_object);
}


void BackgroundTask::Finish()
{
	BNFinishBackgroundTask(m_object);
}


void BackgroundTask::SetProgressText(const string& text)
{
	BNSetBackgroundTaskProgressText(m_object, text.c_str());
}


vector<Ref<BackgroundTask>> BackgroundTask::GetRunningTasks()
{
	size_t count;
	BNBackgroundTask** tasks = BNGetRunningBackgroundTasks(&count);

	vector<Ref<BackgroundTask>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new BackgroundTask(BNNewBackgroundTaskReference(tasks[i])));

	BNFreeBackgroundTaskList(tasks, count);
	return result;
}
