#pragma once
#include <string>
#include <vector>

#include "refcount.hpp"
#include "core/backgroundtask.h"

namespace BinaryNinja {
	class BackgroundTask :
		public CoreRefCountObject<BNBackgroundTask, BNNewBackgroundTaskReference, BNFreeBackgroundTask>
	{
	  public:
		BackgroundTask(BNBackgroundTask* task);
		BackgroundTask(const std::string& initialText, bool canCancel);

		bool CanCancel() const;
		bool IsCancelled() const;
		bool IsFinished() const;
		std::string GetProgressText() const;

		void Cancel();
		void Finish();
		void SetProgressText(const std::string& text);

		static std::vector<Ref<BackgroundTask>> GetRunningTasks();
	};
}