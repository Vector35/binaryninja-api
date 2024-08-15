#pragma once

#include "Resolver.h"

class PeiResolver : Resolver {
    bool resolvePeiIdt();
    bool resolvePeiMrc();
    bool resolvePeiMrs();
    bool resolvePlatformPointers();
    bool resolvePeiDescriptors();
    bool resolvePeiServices();

public:
    /*!
    resolve Pei related types and PPIs, this function will also resolve processor-specific pointers
    and tried to define the EFI_PEI_DESCRIPTORS
    */
    bool resolvePei();
    PeiResolver(Ref<BinaryView> view, Ref<BackgroundTask> task);
};