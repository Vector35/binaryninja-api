#pragma once

#include "Resolver.h"

class DxeResolver : Resolver {
    bool resolveBootServices();
    bool resolveRuntimeServices();

    bool resolveSmmTables(string serviceName, string tableName);
    bool resolveSmmServices();
    bool resolveSmiHandlers();

public:
    /*!
    resolve BootServices and RuntimeServices, define protocol types that loaded by BootServices
    */
    bool resolveDxe();

    /*!
    Define MMST/SMMST and resolve SMM related protocols
    */
    bool resolveSmm();

    DxeResolver(Ref<BinaryView> view, Ref<BackgroundTask> task);
};