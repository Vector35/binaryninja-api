#pragma once

#include "Resolver.h"

class PeiResolver : public Resolver
{
	bool resolvePeiIdt();
	bool resolvePeiMrc();
	bool resolvePeiMrs();
public:
	// Individual phases require completed analysis between calls.
	bool resolvePlatformPointers();
	bool resolveServicePointers();
	bool resolvePeiDescriptors();
	bool resolvePeiServices();

	PeiResolver(Ref<BinaryView> view, Ref<BackgroundTask> task, TypePropagation& propagation);
};
