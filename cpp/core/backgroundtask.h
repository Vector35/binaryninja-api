#pragma once
#include "core/binaryninja_defs.h"

extern "C" {
	struct BNBackgroundTask;
	// Background task progress reporting
	BINARYNINJACOREAPI BNBackgroundTask* BNBeginBackgroundTask(const char* initialText, bool canCancel);
	BINARYNINJACOREAPI void BNFinishBackgroundTask(BNBackgroundTask* task);
	BINARYNINJACOREAPI void BNSetBackgroundTaskProgressText(BNBackgroundTask* task, const char* text);
	BINARYNINJACOREAPI bool BNIsBackgroundTaskCancelled(BNBackgroundTask* task);

	BINARYNINJACOREAPI BNBackgroundTask** BNGetRunningBackgroundTasks(size_t* count);
	BINARYNINJACOREAPI BNBackgroundTask* BNNewBackgroundTaskReference(BNBackgroundTask* task);
	BINARYNINJACOREAPI void BNFreeBackgroundTask(BNBackgroundTask* task);
	BINARYNINJACOREAPI void BNFreeBackgroundTaskList(BNBackgroundTask** tasks, size_t count);
	BINARYNINJACOREAPI char* BNGetBackgroundTaskProgressText(BNBackgroundTask* task);
	BINARYNINJACOREAPI bool BNCanCancelBackgroundTask(BNBackgroundTask* task);
	BINARYNINJACOREAPI void BNCancelBackgroundTask(BNBackgroundTask* task);
	BINARYNINJACOREAPI bool BNIsBackgroundTaskFinished(BNBackgroundTask* task);
}