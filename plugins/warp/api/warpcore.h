#pragma once

#ifndef BN_TYPE_PARSER
#ifdef __cplusplus
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#else
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#endif
#endif

#ifdef __GNUC__
    #ifdef WARP_LIBRARY
        #define WARP_FFI_API __attribute__((visibility("default")))
    #else  // WARP_LIBRARY
        #define WARP_FFI_API
    #endif  // WARP_LIBRARY
#else       // __GNUC__
    #ifdef _MSC_VER
        #ifndef DEMO_VERSION
            #ifdef WARP_LIBRARY
                #define WARP_FFI_API __declspec(dllexport)
            #else  // WARP_LIBRARY
                #define WARP_FFI_API __declspec(dllimport)
            #endif  // WARP_LIBRARY
        #else
            #define WARP_FFI_API
        #endif
    #else  // _MSC_VER
        #define WARP_FFI_API
    #endif  // _MSC_VER
#endif      // __GNUC__C

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct BNArchitecture BNArchitecture;
    typedef struct BNBinaryView BNBinaryView;
    typedef struct BNPlatform BNPlatform;
    typedef struct BNBasicBlock BNBasicBlock;
    typedef struct BNLowLevelILFunction BNLowLevelILFunction;
    typedef struct BNFunction BNFunction;
    typedef struct BNSymbol BNSymbol;
    typedef struct BNType BNType;

    struct BNWARPUUID
    {
        uint8_t uuid[16];
    };

    struct BNWARPFunctionComment
    {
        char* text;
        int64_t offset;
    };

    char* BNWARPUUIDGetString(const BNWARPUUID* uuid);
    bool BNWARPUUIDFromString(const char* str, BNWARPUUID* uuid);
    bool BNWARPUUIDEqual(const BNWARPUUID* a, const BNWARPUUID* b);
    void BNWARPFreeUUIDList(BNWARPUUID* uuids, size_t count);

    typedef BNWARPUUID BNWARPSource;
    typedef BNWARPUUID BNWARPBasicBlockGUID;
    typedef BNWARPUUID BNWARPConstraintGUID;
    typedef BNWARPUUID BNWARPFunctionGUID;
    typedef BNWARPUUID BNWARPTypeGUID;

    typedef struct BNWARPTarget BNWARPTarget;
    typedef struct BNWARPContainer BNWARPContainer;
    typedef struct BNWARPFunction BNWARPFunction;
    typedef struct BNWARPConstraint BNWARPConstraint;
    typedef struct BNWARPContainerSearchQuery BNWARPContainerSearchQuery;
    typedef struct BNWARPContainerSearchItem BNWARPContainerSearchItem;

    enum BNWARPContainerSearchItemKind
    {
        WARPContainerSearchItemKindSource = 0,
        WARPContainerSearchItemKindFunction = 1,
        WARPContainerSearchItemKindType = 2,
        WARPContainerSearchItemKindSymbol = 3,
    };

    struct BNWARPContainerSearchResponse
    {
        size_t count;
        BNWARPContainerSearchItem** items;
        size_t offset;
        size_t total;
    };

    struct BNWARPConstraint
    {
        BNWARPConstraintGUID guid;
        int64_t offset;
    };

    WARP_FFI_API void BNWARPRunMatcher(BNBinaryView* view);
    
    WARP_FFI_API bool BNWARPGetBasicBlockGUID(BNBasicBlock* basicBlock, BNWARPBasicBlockGUID* result);
    WARP_FFI_API bool BNWARPGetAnalysisFunctionGUID(BNFunction* analysisFunction, BNWARPFunctionGUID* result);
    WARP_FFI_API bool BNWARPIsLiftedInstructionVariant(BNLowLevelILFunction* liftedFunction, size_t idx);
    WARP_FFI_API bool BNWARPIsLiftedInstructionBlacklisted(BNLowLevelILFunction* liftedFunction, size_t idx);
    WARP_FFI_API bool BNWARPIsLowLevelInstructionComputedVariant(BNLowLevelILFunction* llilFunction, size_t idx);

    WARP_FFI_API BNWARPFunction* BNWARPGetFunction(BNFunction* analysisFunction);
    WARP_FFI_API BNWARPFunction* BNWARPGetMatchedFunction(BNFunction* analysisFunction);
    WARP_FFI_API BNWARPContainer** BNWARPGetContainers(size_t* count);

    WARP_FFI_API char* BNWARPContainerGetName(BNWARPContainer* container);

    WARP_FFI_API BNWARPSource* BNWARPContainerGetSources(BNWARPContainer* container, size_t* count);
    WARP_FFI_API bool BNWARPContainerAddSource(BNWARPContainer* container, const char* sourcePath, BNWARPSource* result);
    WARP_FFI_API bool BNWARPContainerCommitSource(BNWARPContainer* container, const BNWARPSource* source);
    WARP_FFI_API bool BNWARPContainerIsSourceUncommitted(BNWARPContainer* container, const BNWARPSource* source);
    WARP_FFI_API bool BNWARPContainerIsSourceWritable(BNWARPContainer* container, const BNWARPSource* source);
    WARP_FFI_API char* BNWARPContainerGetSourcePath(BNWARPContainer* container, const BNWARPSource* source);
    
    WARP_FFI_API bool BNWARPContainerAddFunctions(BNWARPContainer* container, const BNWARPTarget* target, const BNWARPSource* source, BNWARPFunction** functions, size_t count);
    WARP_FFI_API bool BNWARPContainerAddTypes(BNBinaryView* view, BNWARPContainer* container, const BNWARPSource* source, BNType** types, size_t count);

    WARP_FFI_API bool BNWARPContainerRemoveFunctions(BNWARPContainer* container, const BNWARPTarget* target, const BNWARPSource* source, BNWARPFunction** functions, size_t count);
    WARP_FFI_API bool BNWARPContainerRemoveTypes(BNWARPContainer* container, const BNWARPSource* source, BNWARPTypeGUID* types, size_t count);

    WARP_FFI_API void BNWARPContainerFetchFunctions(BNWARPContainer* container, BNWARPTarget* target, const char** sourceTags, size_t sourceTagCount, const BNWARPTypeGUID* guids, size_t count);
    
    WARP_FFI_API BNWARPSource* BNWARPContainerGetSourcesWithFunctionGUID(BNWARPContainer* container, const BNWARPTarget* target, const BNWARPFunctionGUID* guid, size_t* count);
    WARP_FFI_API BNWARPSource* BNWARPContainerGetSourcesWithTypeGUID(BNWARPContainer* container, const BNWARPTypeGUID* guid, size_t* count);
    WARP_FFI_API BNWARPFunction** BNWARPContainerGetFunctionsWithGUID(BNWARPContainer* container, const BNWARPTarget* target, const BNWARPSource* source, const BNWARPFunctionGUID* guid, size_t* count);
    WARP_FFI_API BNType* BNWARPContainerGetTypeWithGUID(BNArchitecture* arch, BNWARPContainer* container, const BNWARPSource* source, const BNWARPTypeGUID* guid);
    WARP_FFI_API BNWARPTypeGUID* BNWARPContainerGetTypeGUIDsWithName(BNWARPContainer* container, const BNWARPSource* source, const char* name, size_t* count);

    WARP_FFI_API BNWARPContainer* BNWARPNewContainerReference(BNWARPContainer* container);
    WARP_FFI_API void BNWARPFreeContainerReference(BNWARPContainer* container);
    WARP_FFI_API void BNWARPFreeContainerList(BNWARPContainer** containers, size_t count);

    WARP_FFI_API BNWARPContainerSearchQuery* BNWARPNewContainerSearchQuery(const char* query, const size_t* offset, const size_t* limit, const BNWARPSource* source, const char** sourceTags, size_t sourceTagCount);

    WARP_FFI_API BNWARPContainerSearchResponse* BNWARPContainerSearch(BNWARPContainer* container, const BNWARPContainerSearchQuery* query);

    WARP_FFI_API BNWARPContainerSearchItemKind BNWARPContainerSearchItemGetKind(BNWARPContainerSearchItem* item);
    WARP_FFI_API BNWARPSource BNWARPContainerSearchItemGetSource(BNWARPContainerSearchItem* item);
    WARP_FFI_API BNType* BNWARPContainerSearchItemGetType(BNArchitecture* arch, BNWARPContainerSearchItem* item);
    WARP_FFI_API char* BNWARPContainerSearchItemGetName(BNWARPContainerSearchItem* item);
    WARP_FFI_API BNWARPFunction* BNWARPContainerSearchItemGetFunction(BNWARPContainerSearchItem* item);

    WARP_FFI_API BNWARPContainerSearchQuery* BNWARPNewContainerSearchQueryReference(BNWARPContainerSearchQuery* query);
    WARP_FFI_API void BNWARPFreeContainerSearchQueryReference(BNWARPContainerSearchQuery* query);

    WARP_FFI_API BNWARPContainerSearchItem* BNWARPNewContainerSearchItemReference(BNWARPContainerSearchItem* item);
    WARP_FFI_API void BNWARPFreeContainerSearchItemReference(BNWARPContainerSearchItem* item);
    WARP_FFI_API void BNWARPFreeContainerSearchItemList(BNWARPContainerSearchItem** items, size_t count);

    WARP_FFI_API void BNWARPFreeContainerSearchResponse(BNWARPContainerSearchResponse* response);

    WARP_FFI_API void BNWARPFunctionApply(BNWARPFunction* function, BNFunction* analysisFunction);
    WARP_FFI_API BNWARPFunctionGUID BNWARPFunctionGetGUID(BNWARPFunction* function);
    WARP_FFI_API BNSymbol* BNWARPFunctionGetSymbol(BNWARPFunction* function, BNFunction* analysisFunction);
    WARP_FFI_API char* BNWARPFunctionGetSymbolName(BNWARPFunction* function);
    WARP_FFI_API BNType* BNWARPFunctionGetType(BNWARPFunction* function, BNFunction* analysisFunction);
    WARP_FFI_API BNWARPConstraint* BNWARPFunctionGetConstraints(BNWARPFunction* function, size_t* count);
    WARP_FFI_API BNWARPFunctionComment* BNWARPFunctionGetComments(BNWARPFunction* function, size_t* count);
    WARP_FFI_API bool BNWARPFunctionsEqual(BNWARPFunction* functionA, BNWARPFunction* functionB);

    WARP_FFI_API void BNWARPFreeFunctionCommentList(BNWARPFunctionComment* comments, size_t count);
    WARP_FFI_API void BNWARPFreeConstraintList(BNWARPConstraint* constraints, size_t count);

    WARP_FFI_API BNWARPFunction* BNWARPNewFunctionReference(BNWARPFunction* function);
    WARP_FFI_API void BNWARPFreeFunctionReference(BNWARPFunction* function);
    WARP_FFI_API void BNWARPFreeFunctionList(BNWARPFunction** functions, size_t count);

    WARP_FFI_API BNWARPTarget* BNWARPGetTarget(BNPlatform* platform);

    WARP_FFI_API BNWARPTarget* BNWARPNewTargetReference(BNWARPTarget* target);
    WARP_FFI_API void BNWARPFreeTargetReference(BNWARPTarget* target);

#ifdef __cplusplus
}
#endif
