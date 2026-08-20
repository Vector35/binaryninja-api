#pragma once

class SharedCacheWorkflow
{
public:
	static void Register();
};

#ifdef __cplusplus
extern "C" {
#endif
	void RegisterSharedCacheWorkflow();
#ifdef __cplusplus
}
#endif
