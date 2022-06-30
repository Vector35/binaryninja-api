#pragma once

#ifdef __cplusplus
extern "C"
{
#endif
	enum BNPluginLoadOrder
	{
		EarlyPluginLoadOrder,
		NormalPluginLoadOrder,
		LatePluginLoadOrder
	};

	enum PluginLoadStatus
	{
		NotAttemptedStatus,
		LoadSucceededStatus,
		LoadFailedStatus
	};

	typedef bool (*BNCorePluginInitFunction)(void);
	typedef void (*BNCorePluginDependencyFunction)(void);
	typedef uint32_t (*BNCorePluginABIVersionFunction)(void);

}