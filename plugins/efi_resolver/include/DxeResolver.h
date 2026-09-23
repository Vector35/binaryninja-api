#pragma once

#include "Resolver.h"

class DxeResolver : public Resolver
{
	bool resolveBootServices();
	bool resolveRuntimeServices();
	bool resolveProtocolGuid(Ref<Function> func, uint64_t addr, size_t guidParam);
	bool resolveProtocolInterfaces(Ref<Function> func, uint64_t addr, size_t guidParam, const vector<size_t>& interfaceParams);
	bool resolveProtocolInterfaceList(Ref<Function> func, uint64_t addr, size_t firstGuidParam);

public:
	// Individual phases require completed analysis between calls.
	bool resolveSmmTables(string serviceName, string tableName);
	bool resolveSmmServices();
	bool resolveSmiHandlers();

	/*!
	resolve BootServices and RuntimeServices, define protocol types that loaded by BootServices
	*/
	bool resolveDxe();

	DxeResolver(Ref<BinaryView> view, Ref<BackgroundTask> task, TypePropagation& propagation);
};
