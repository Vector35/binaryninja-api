#pragma once

#include "binaryninjaapi.h"

namespace BinaryNinja {
    struct BaseClassArray
    {
        uint32_t length;
        std::vector<uint64_t> descriptors;

        BaseClassArray(BinaryView* view, uint64_t address, uint32_t length);
    };

    struct ClassHierarchyDescriptor
    {
        uint32_t signature;
        uint32_t attributes;
        uint32_t numBaseClasses;
        int32_t pBaseClassArray;

        ClassHierarchyDescriptor(BinaryView* view, uint64_t address);
    };

    struct BaseClassDescriptor
    {
        int32_t pTypeDescriptor;
        uint32_t numContainedBases;
        int32_t where_mdisp;
        int32_t where_pdisp;
        int32_t where_vdisp;
        uint32_t attributes;
        int32_t pClassHierarchyDescriptor;

        BaseClassDescriptor(BinaryView* view, uint64_t address);
    };

    struct TypeDescriptor
    {
        uint64_t pVFTable;
        uint64_t spare;
        std::string name;

        TypeDescriptor(BinaryView* view, uint64_t address);
    };

    struct CompleteObjectLocator
    {
        uint32_t signature;
        uint32_t offset;
        uint32_t cdOffset;
        int32_t pTypeDescriptor;
        int32_t pClassHeirarchyDescriptor;
        // Only on 64 bit
        int32_t pSelf;

        CompleteObjectLocator(BinaryView *view, uint64_t address);
    };

    struct ClassInfo
    {
        std::string className;
        std::optional<std::string> baseClassName;
    };

    class MicrosoftRTTIProcessor
    {
        BinaryView* m_view;
        Ref<Logger> m_logger;
        bool processVirtualFunctionTables;
        bool allowMangledClassNames;
        bool checkWritableRData;

        std::optional<std::string> DemangleName(const std::string& mangledName);
        std::optional<ClassInfo> ProcessRTTI(uint64_t coLocatorAddr);
        void ProcessVFT(uint64_t vftAddr, const ClassInfo& classInfo);
    public:
        MicrosoftRTTIProcessor(BinaryView* view, bool processVFT, bool useMangled, bool checkRData);
        void ProcessRTTI64();
        void ProcessRTTI32();
    };
}