// Have some overlap with likely-called functions so ld on
// linux doesn't skip linking liblinkhack
void BNLog() {}
void BNLogDebug() {}
void BNLogInfo() {}
void BNLogWarn() {}
void BNLogError() {}
void BNLogAlert() {}
void BNShutdown() {}
void BNNewViewReference() {}
void BNFreeBinaryView() {}
void BNInitCorePlugins() {}
void BNAllocString() {}
void BNFreeString() {}
void BNRegisterBinaryViewType() {}
void BNGetArchitectureList() {}
void BNNewFunctionReference() {}
void BNFreeFunction() {}
void BNGetFunctionBasicBlockList() {}
void BNRegisterArchitecture() {}
