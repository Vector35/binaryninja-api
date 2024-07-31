#include "rtti.h"

#include <utility>

using namespace BinaryNinja;

constexpr int COL_SIG_REV1 = 1;
constexpr int RTTI_CONFIDENCE = 100;


ClassHierarchyDescriptor::ClassHierarchyDescriptor(BinaryView *view, uint64_t address)
{
    BinaryReader reader = BinaryReader(view);
    reader.Seek(address);
    signature = reader.Read32();
    attributes = reader.Read32();
    numBaseClasses = reader.Read32();
    pBaseClassArray = (int32_t)reader.Read32();
}


BaseClassDescriptor::BaseClassDescriptor(BinaryView *view, uint64_t address)
{
    BinaryReader reader = BinaryReader(view);
    reader.Seek(address);
    pTypeDescriptor = (int32_t)reader.Read32();
    numContainedBases = reader.Read32();
    where_mdisp = (int32_t)reader.Read32();
    where_pdisp = (int32_t)reader.Read32();
    where_vdisp = (int32_t)reader.Read32();
    attributes = reader.Read32();
    pClassHierarchyDescriptor = (int32_t)reader.Read32();
}


BaseClassArray::BaseClassArray(BinaryView *view, uint64_t address, uint32_t length) : length(length)
{
    BinaryReader reader = BinaryReader(view);
    reader.Seek(address);
    descriptors = {};
    for (size_t i = 0; i < length; i++)
        descriptors.emplace_back(reader.Read32());
}


TypeDescriptor::TypeDescriptor(BinaryView *view, uint64_t address)
{
    BinaryReader reader = BinaryReader(view);
    reader.Seek(address);
    pVFTable = reader.ReadPointer();
    spare = reader.ReadPointer();
    name = reader.ReadCString(512);
}


CompleteObjectLocator::CompleteObjectLocator(BinaryView *view, uint64_t address)
{
    BinaryReader reader = BinaryReader(view);
    reader.Seek(address);
    signature = reader.Read32();
    offset = reader.Read32();
    cdOffset = reader.Read32();
    pTypeDescriptor = (int32_t)reader.Read32();
    pClassHeirarchyDescriptor = (int32_t)reader.Read32();
    if (signature == COL_SIG_REV1)
    {
        pSelf = (int32_t)reader.Read32();
    }
    else
    {
        pSelf = 0;
    }
}


std::optional<CompleteObjectLocator> ReadCompleteObjectorLocator(BinaryView *view, uint64_t address)
{
    auto coLocator = CompleteObjectLocator(view, address);
    uint64_t startAddr = view->GetStart();
    uint64_t endAddr = view->GetEnd();

    if (coLocator.signature > 1)
        return std::nullopt;

    if (coLocator.signature == COL_SIG_REV1)
    {
        if (coLocator.pSelf != address - startAddr)
            return std::nullopt;

        // Relative addrs
        if (coLocator.pTypeDescriptor + startAddr > endAddr)
            return std::nullopt;

        if (coLocator.pClassHeirarchyDescriptor + startAddr > endAddr)
            return std::nullopt;
    }
    else
    {
        // Absolute addrs
        if (coLocator.pTypeDescriptor < startAddr || coLocator.pTypeDescriptor > endAddr)
            return std::nullopt;

        if (coLocator.pClassHeirarchyDescriptor < startAddr || coLocator.pClassHeirarchyDescriptor > endAddr)
            return std::nullopt;
    }

    return coLocator;
}


Ref<Type> GetPMDType(BinaryView* view)
{
    auto typeId = Type::GenerateAutoTypeId("msvc_rtti", QualifiedName("PMD"));
    Ref<Type> typeCache = view->GetTypeById(typeId);

    if (typeCache == nullptr)
    {
        Ref<Type> intType = Type::IntegerType(4, true);

        StructureBuilder pmdBuilder;
        pmdBuilder.AddMember(intType, "mdisp");
        pmdBuilder.AddMember(intType, "pdisp");
        pmdBuilder.AddMember(intType, "vdisp");

        view->DefineType(typeId, QualifiedName("_PMD"), TypeBuilder::StructureType(&pmdBuilder).Finalize());
        typeCache = view->GetTypeById(typeId);
    }

    return typeCache;
}


Ref<Type> ClassHierarchyDescriptorType(BinaryView* view);
Ref<Type> BaseClassDescriptorType(BinaryView* view)
{
    auto typeId = Type::GenerateAutoTypeId("msvc_rtti", QualifiedName("RTTIBaseClassDescriptor"));
    Ref<Type> typeCache = view->GetTypeById(typeId);

    if (typeCache == nullptr)
    {
        Ref<Type> uintType = Type::IntegerType(4, false);

        StructureBuilder baseClassDescriptorBuilder;
        // Would require creating a new type for every type descriptor length. Instead just use void*
        Ref<Type> pTypeDescType = TypeBuilder::PointerType(4, Type::VoidType())
            .SetPointerBase(RelativeToBinaryStartPointerBaseType, 0)
            .Finalize();
        baseClassDescriptorBuilder.AddMember(pTypeDescType, "pTypeDescriptor");
        baseClassDescriptorBuilder.AddMember(uintType, "numContainedBases");
        baseClassDescriptorBuilder.AddMember(GetPMDType(view), "where");
        baseClassDescriptorBuilder.AddMember(uintType, "attributes");
        Ref<Type> pClassDescType = TypeBuilder::PointerType(4, ClassHierarchyDescriptorType(view))
            .SetPointerBase(RelativeToBinaryStartPointerBaseType, 0)
            .Finalize();
        baseClassDescriptorBuilder.AddMember(pClassDescType, "pClassDescriptor");

        view->DefineType(typeId, QualifiedName("_RTTIBaseClassDescriptor"),
            TypeBuilder::StructureType(&baseClassDescriptorBuilder).Finalize());
        typeCache = view->GetTypeById(typeId);
    }

    return typeCache;
}


Ref<Type> BaseClassArrayType(BinaryView* view, const uint64_t length)
{
    StructureBuilder baseClassArrayBuilder;
    Ref<Type> pBaseClassDescType = TypeBuilder::PointerType(4, BaseClassDescriptorType(view))
        .SetPointerBase(RelativeToBinaryStartPointerBaseType, 0)
        .Finalize();
    baseClassArrayBuilder.AddMember(
        Type::ArrayType(pBaseClassDescType, length), "arrayOfBaseClassDescriptors");
    return TypeBuilder::StructureType(&baseClassArrayBuilder).Finalize();
}


Ref<Type> ClassHierarchyDescriptorType(BinaryView* view)
{
    auto typeId = Type::GenerateAutoTypeId("msvc_rtti", QualifiedName("RTTIClassHierarchyDescriptor"));
    Ref<Type> typeCache = view->GetTypeById(typeId);

    if (typeCache == nullptr)
    {
        Ref<Type> uintType = Type::IntegerType(4, false);

        StructureBuilder classHierarchyDescriptorBuilder;
        classHierarchyDescriptorBuilder.AddMember(uintType, "signature");
        classHierarchyDescriptorBuilder.AddMember(uintType, "attributes");
        classHierarchyDescriptorBuilder.AddMember(uintType, "numBaseClasses");
        Ref<Type> pBaseClassArrayType = TypeBuilder::PointerType(4, Type::VoidType())
            .SetPointerBase(RelativeToBinaryStartPointerBaseType, 0)
            .Finalize();
        classHierarchyDescriptorBuilder.AddMember(pBaseClassArrayType, "pBaseClassArray");

        view->DefineType(typeId, QualifiedName("_RTTIClassHierarchyDescriptor"),
            TypeBuilder::StructureType(&classHierarchyDescriptorBuilder).Finalize());

        typeCache = view->GetTypeById(typeId);
    }

    return typeCache;
}


Ref<Type> CompleteObjectLocator64Type(BinaryView *view)
{
    auto typeId = Type::GenerateAutoTypeId("msvc_rtti", QualifiedName("RTTICompleteObjectLocator64"));
    Ref<Type> typeCache = view->GetTypeById(typeId);

    if (typeCache == nullptr)
    {
        Ref<Architecture> arch = view->GetDefaultArchitecture();
        Ref<Type> uintType = Type::IntegerType(4, false);

        StructureBuilder completeObjectLocatorBuilder;
        Ref<Enumeration> sigEnum = EnumerationBuilder()
            .AddMemberWithValue("COL_SIG_REV0", 0)
            .AddMemberWithValue("COL_SIG_REV1", 1)
            .Finalize();
        Ref<Type> sigType = Type::EnumerationType(arch, sigEnum, 4);
        completeObjectLocatorBuilder.AddMember(sigType, "signature");
        completeObjectLocatorBuilder.AddMember(uintType, "offset");
        completeObjectLocatorBuilder.AddMember(uintType, "cdOffset");
        Ref<Type> pTypeDescType = TypeBuilder::PointerType(4, Type::VoidType())
            .SetPointerBase(RelativeToBinaryStartPointerBaseType, 0)
            .Finalize();
        completeObjectLocatorBuilder.AddMember(pTypeDescType, "pTypeDescriptor");
        Ref<Type> pClassHierarchyDescType = TypeBuilder::PointerType(4, ClassHierarchyDescriptorType(view))
            .SetPointerBase(RelativeToBinaryStartPointerBaseType, 0)
            .Finalize();
        completeObjectLocatorBuilder.AddMember(pClassHierarchyDescType, "pClassHierarchyDescriptor");
        Ref<Type> pSelfType = TypeBuilder::PointerType(4, Type::NamedType(view, typeId))
            .SetPointerBase(RelativeToBinaryStartPointerBaseType, 0)
            .Finalize();
        completeObjectLocatorBuilder.AddMember(pSelfType, "pSelf");

        view->DefineType(typeId, QualifiedName("_RTTICompleteObjectLocator"),
                         TypeBuilder::StructureType(&completeObjectLocatorBuilder).Finalize());

        typeCache = view->GetTypeById(typeId);
    }

    return typeCache;
}


Ref<Type> TypeDescriptorType(BinaryView* view, uint64_t length)
{
    size_t addrSize = view->GetAddressSize();
    StructureBuilder typeDescriptorBuilder;
    typeDescriptorBuilder.AddMember(Type::PointerType(addrSize, Type::VoidType(), true), "pVFTable");
    typeDescriptorBuilder.AddMember(Type::PointerType(addrSize, Type::VoidType()), "spare");
    // Char array needs to be individually resized.
    typeDescriptorBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true, "char"), length), "name");
    return TypeBuilder::StructureType(&typeDescriptorBuilder).Finalize();
}


std::optional<std::string> MicrosoftRTTIProcessor::DemangleName(const std::string& mangledName)
{
    QualifiedName demangledName = {};
    Ref<Type> outType = {};
    if (!DemangleMS(m_view->GetDefaultArchitecture(), mangledName, outType, demangledName, true))
        return allowMangledClassNames ? std::optional(mangledName) : std::nullopt;
    return demangledName.GetString();
}


std::optional<ClassInfo> MicrosoftRTTIProcessor::ProcessRTTI(uint64_t coLocatorAddr)
{
    // Get complete object locator then check to see if its valid.
    auto coLocator = ReadCompleteObjectorLocator(m_view, coLocatorAddr);
    if (!coLocator.has_value())
        return std::nullopt;

    auto startAddr = m_view->GetStart();
    auto resolveAddr = [&](const uint64_t relAddr) {
        return coLocator->signature == COL_SIG_REV1 ? startAddr + relAddr : relAddr;
    };

    // Get type descriptor then check to see if the class name was demangled.
    auto typeDescAddr = resolveAddr(coLocator->pTypeDescriptor);
    auto typeDesc = TypeDescriptor(m_view, typeDescAddr);
    auto className = DemangleName(typeDesc.name);
    if (!className.has_value())
        return std::nullopt;

    auto classInfo = ClassInfo { className.value() };

    auto typeDescSymName = fmt::format("class {} `RTTI Type Descriptor'", classInfo.className);
    m_view->DefineAutoSymbol(new Symbol {DataSymbol, typeDescSymName, typeDescAddr});
    m_view->DefineDataVariable(typeDescAddr, Confidence(TypeDescriptorType(m_view, typeDesc.name.length()), RTTI_CONFIDENCE));

    auto classHierarchyDescAddr = resolveAddr(coLocator->pClassHeirarchyDescriptor);
    auto classHierarchyDesc = ClassHierarchyDescriptor(m_view, classHierarchyDescAddr);
    auto classHierarchyDescName = fmt::format("{}::`RTTI Class Hierarchy Descriptor'", classInfo.className);
    m_view->DefineAutoSymbol(new Symbol {DataSymbol, classHierarchyDescName, classHierarchyDescAddr});
    m_view->DefineDataVariable(classHierarchyDescAddr, Confidence(ClassHierarchyDescriptorType(m_view), RTTI_CONFIDENCE));

    auto baseClassArrayAddr = resolveAddr(classHierarchyDesc.pBaseClassArray);
    auto baseClassArray = BaseClassArray(m_view, baseClassArrayAddr, classHierarchyDesc.numBaseClasses);
    auto baseClassArrayName = fmt::format("{}::`RTTI Base Class Array'", classInfo.className);
    m_view->DefineAutoSymbol(new Symbol {DataSymbol, baseClassArrayName, baseClassArrayAddr});
    m_view->DefineDataVariable(baseClassArrayAddr, Confidence(BaseClassArrayType(m_view, baseClassArray.length), RTTI_CONFIDENCE));

    for (auto pBaseClassDescAddr : baseClassArray.descriptors)
    {
        auto baseClassDescAddr = resolveAddr(pBaseClassDescAddr);
        auto baseClassDesc = BaseClassDescriptor(m_view, baseClassDescAddr);

        auto baseClassTypeDescAddr = resolveAddr(baseClassDesc.pTypeDescriptor);
        auto baseClassTypeDesc = TypeDescriptor(m_view, baseClassTypeDescAddr);
        auto baseClassName = DemangleName(baseClassTypeDesc.name);
        if (!baseClassName.has_value())
        {
            m_logger->LogWarn("Skipping BaseClassDescriptor with mangled name %llx", baseClassTypeDescAddr);
            continue;
        }

        if (coLocator->offset > 0 && baseClassDesc.where_mdisp == coLocator->offset)
            classInfo.baseClassName = baseClassName;

        auto baseClassDescName = fmt::format("{}::`RTTI Base Class Descriptor at ({},{},{},{})", baseClassName.value(),
                                             baseClassDesc.where_mdisp, baseClassDesc.where_pdisp,
                                             baseClassDesc.where_vdisp, baseClassDesc.attributes);
        m_view->DefineAutoSymbol(new Symbol {DataSymbol, baseClassDescName, baseClassDescAddr});
        m_view->DefineDataVariable(baseClassDescAddr, Confidence(BaseClassDescriptorType(m_view), RTTI_CONFIDENCE));
    }

    auto coLocatorName = fmt::format("{}::`RTTI Complete Object Locator'", className.value());
    if (classInfo.baseClassName.has_value())
        coLocatorName += fmt::format("{{for `{}'}}", classInfo.baseClassName.value());
    m_view->DefineAutoSymbol(new Symbol {DataSymbol, coLocatorName, coLocatorAddr});
    if (coLocator->signature == COL_SIG_REV1)
        m_view->DefineDataVariable(coLocatorAddr, Confidence(CompleteObjectLocator64Type(m_view), RTTI_CONFIDENCE));
    else
        m_logger->LogDebug("COL_SIG_REV0 unsupported symbolizing of colocator...");

    return classInfo;
}


void MicrosoftRTTIProcessor::ProcessVFT(uint64_t vftAddr, const ClassInfo& classInfo)
{
    // Gather all virtual functions
    BinaryReader reader = BinaryReader(m_view);
    reader.Seek(vftAddr);
    std::vector<Ref<Function>> virtualFunctions = {};
    while (true)
    {
        uint64_t vFuncAddr = reader.ReadPointer();
        auto funcs = m_view->GetAnalysisFunctionsForAddress(vFuncAddr);
        if (funcs.empty())
        {
            Ref<Segment> segment = m_view->GetSegmentAt(vFuncAddr);
            if (segment == nullptr || !(segment->GetFlags() & (SegmentExecutable | SegmentDenyWrite)))
            {
                // Last CompleteObjectLocator or hit the next CompleteObjectLocator
                break;
            }

            m_logger->LogDebug("Discovered function from virtual function table... %llx", vFuncAddr);
            auto vFunc = m_view->AddFunctionForAnalysis(m_view->GetDefaultPlatform(), vFuncAddr, true);
            funcs.emplace_back(vFunc);
        }
        // Add back the virtual functions to virtual function list
        virtualFunctions.reserve(virtualFunctions.size() + std::distance(funcs.begin(),funcs.end()));
        virtualFunctions.insert(virtualFunctions.end(),funcs.begin(),funcs.end());
    }

    // Create virtual function table type
    auto vftTypeName = fmt::format("{}::VTable",
                                   classInfo.baseClassName.has_value()
                                       ? classInfo.baseClassName.value()
                                       : classInfo.className);
    // TODO: Hack the debug type id is used here to allow the PDB type (debug info) to overwrite the RTTI vtable type.
    auto typeId = Type::GenerateAutoDebugTypeId(vftTypeName);
    Ref<Type> vftType = m_view->GetTypeById(typeId);

    if (vftType == nullptr)
    {
        size_t addrSize = m_view->GetAddressSize();
        StructureBuilder vftBuilder = {};
        vftBuilder.SetPropagateDataVariableReferences(true);
        size_t vFuncIdx = 0;
        for (auto&& vFunc : virtualFunctions)
        {
            auto vFuncName = fmt::format("vFunc_{}", vFuncIdx);
            // The analyzed function type is not available here.
            vftBuilder.AddMember(
                Type::PointerType(addrSize, vFunc->GetType(), true), vFuncName);
            vFuncIdx++;
        }
        m_view->DefineType(typeId, vftTypeName, Confidence(TypeBuilder::StructureType(&vftBuilder).Finalize(), RTTI_CONFIDENCE));
        vftType = m_view->GetTypeById(typeId);
    }

    auto vftName = fmt::format("{}::`vftable'", classInfo.className);
    if (classInfo.baseClassName.has_value())
        vftName += fmt::format("{{for `{}'}}", classInfo.baseClassName.value());
    m_view->DefineAutoSymbol(new Symbol {DataSymbol, vftName, vftAddr});
    m_view->DefineDataVariable(vftAddr, Confidence(vftType, RTTI_CONFIDENCE));
}


MicrosoftRTTIProcessor::MicrosoftRTTIProcessor(BinaryView *view, bool processVFT, bool useMangled, bool checkRData) : m_view(view)
{
    m_logger = new Logger("Microsoft RTTI");
    processVirtualFunctionTables = processVFT;
    allowMangledClassNames = useMangled;
    checkWritableRData = checkRData;
}


void MicrosoftRTTIProcessor::ProcessRTTI64()
{
    m_logger->LogInfo("Processing 64bit RTTI...");
    uint64_t startAddr = m_view->GetStart();
    BinaryReader optReader = BinaryReader(m_view);
    auto addrSize = m_view->GetAddressSize();

    auto scan64 = [&](const Ref<Segment> &segment) {
        for (uint64_t coLocatorRefAddr = segment->GetStart(); coLocatorRefAddr < segment->GetEnd() - 0x18;
             coLocatorRefAddr += addrSize)
        {
            optReader.Seek(coLocatorRefAddr);
            uint64_t coLocatorAddr = optReader.ReadPointer();
            if (coLocatorAddr > m_view->GetStart() && coLocatorAddr < m_view->GetEnd())
            {
                // Make sure we do not read across segment boundary.
                auto coLocatorSegment = m_view->GetSegmentAt(coLocatorAddr);
                if (coLocatorSegment != nullptr && coLocatorSegment == segment && coLocatorSegment->GetEnd() -
                    coLocatorAddr > 0x18)
                {
                    optReader.Seek(coLocatorAddr);
                    uint32_t sigVal = optReader.Read32();
                    if (sigVal == COL_SIG_REV1)
                    {
                        optReader.SeekRelative(16);
                        if (optReader.Read32() == coLocatorAddr - startAddr)
                        {
                            auto classInfo = ProcessRTTI(coLocatorAddr);
                            if (processVirtualFunctionTables && classInfo.has_value())
                                ProcessVFT(coLocatorRefAddr + addrSize, classInfo.value());
                        }
                    }
                }
            }
        }
    };

    // Scan data sections for colocators.
    auto rdataSection = m_view->GetSectionByName(".rdata");
    for (const Ref<Segment>& segment : m_view->GetSegments())
    {
        if (segment->GetFlags() == (SegmentReadable | SegmentContainsData))
        {
            m_logger->LogDebug("Attempting to find VirtualFunctionTables in segment %llx", segment->GetStart());
            scan64(segment);
        } else if (checkWritableRData && rdataSection && rdataSection->GetStart() == segment->GetStart())
        {
            m_logger->LogDebug("Attempting to find VirtualFunctionTables in writable rdata segment %llx", segment->GetStart());
            scan64(segment);
        }
    }
}

void MicrosoftRTTIProcessor::ProcessRTTI32()
{
    m_logger->LogInfo("Processing 32bit RTTI...");
    uint64_t startAddr = m_view->GetStart();
    BinaryReader optReader = BinaryReader(m_view);
    auto addrSize = m_view->GetAddressSize();

    auto scan32 = [&](const Ref<Segment> &segment) {
        for (uint64_t coLocatorRefAddr = segment->GetStart(); coLocatorRefAddr < segment->GetEnd() - 0x18;
             coLocatorRefAddr += addrSize)
        {
            optReader.Seek(coLocatorRefAddr);
            uint64_t coLocatorAddr = optReader.ReadPointer();
            if (coLocatorAddr > m_view->GetStart() && coLocatorAddr < m_view->GetEnd())
            {
                // Make sure we do not read across segment boundary.
                auto coLocatorSegment = m_view->GetSegmentAt(coLocatorAddr);
                if (coLocatorSegment != nullptr && coLocatorSegment == segment && coLocatorSegment->GetEnd() -
                    coLocatorAddr > 0x18)
                {
                    optReader.Seek(coLocatorAddr);
                    uint32_t sigVal = optReader.Read32();
                    if (sigVal == 0)
                    {
                        // Check ?AV
                        optReader.SeekRelative(8);
                        uint64_t typeDescNameAddr = optReader.Read32() + 8;
                        if (typeDescNameAddr > m_view->GetStart() && typeDescNameAddr < m_view->GetEnd())
                        {
                            // Make sure we do not read across segment boundary.
                            auto typeDescSegment = m_view->GetSegmentAt(typeDescNameAddr);
                            if (typeDescSegment != nullptr && typeDescSegment->GetEnd() - typeDescNameAddr > 4)
                            {
                                optReader.Seek(typeDescNameAddr);
                                if (optReader.ReadString(4) == ".?AV")
                                {
                                    auto classInfo = ProcessRTTI(coLocatorAddr);
                                    if (processVirtualFunctionTables && classInfo.has_value())
                                        ProcessVFT(coLocatorRefAddr + addrSize, classInfo.value());
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    // Scan data sections for colocators.
    auto rdataSection = m_view->GetSectionByName(".rdata");
    for (const Ref<Segment>& segment : m_view->GetSegments())
    {
        if (segment->GetFlags() == (SegmentReadable | SegmentContainsData))
        {
            m_logger->LogDebug("Attempting to find VirtualFunctionTables in segment %llx", segment->GetStart());
            scan32(segment);
        } else if (checkWritableRData && rdataSection && rdataSection->GetStart() == segment->GetStart())
        {
            m_logger->LogDebug("Attempting to find VirtualFunctionTables in writable rdata segment %llx", segment->GetStart());
            scan32(segment);
        }
    }
}

