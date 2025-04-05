#include "microsoft.h"

using namespace BinaryNinja;
using namespace BinaryNinja::RTTI;
using namespace BinaryNinja::RTTI::Microsoft;

constexpr int COL_SIG_REV0 = 0;
constexpr int COL_SIG_REV1 = 1;
constexpr int BCD_HASPCHD = 0x40;

constexpr const char *TYPE_SOURCE_MICROSOFT = "rtti_microsoft";


// This is used internally when processing a `CompleteObjectLocator`.
struct CompleteObjectLocatorInfo
{
    uint64_t classOffset = 0;
    std::optional<std::string> baseClassName;
    std::optional<uint64_t> baseVft;
};


ClassHierarchyDescriptor::ClassHierarchyDescriptor(BinaryView *view, uint64_t address)
{
    BinaryReader reader = BinaryReader(view);
    reader.Seek(address);
    signature = reader.Read32();
    attributes = reader.Read32();
    numBaseClasses = reader.Read32();
    pBaseClassArray = static_cast<int32_t>(reader.Read32());
}


BaseClassDescriptor::BaseClassDescriptor(BinaryView *view, uint64_t address)
{
    BinaryReader reader = BinaryReader(view);
    reader.Seek(address);
    pTypeDescriptor = static_cast<int32_t>(reader.Read32());
    numContainedBases = reader.Read32();
    where_mdisp = static_cast<int32_t>(reader.Read32());
    where_pdisp = static_cast<int32_t>(reader.Read32());
    where_vdisp = static_cast<int32_t>(reader.Read32());
    attributes = reader.Read32();
    pClassHierarchyDescriptor = static_cast<int32_t>(reader.Read32());
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
    pTypeDescriptor = static_cast<int32_t>(reader.Read32());
    pClassHierarchyDescriptor = static_cast<int32_t>(reader.Read32());
    if (signature == COL_SIG_REV1)
    {
        pSelf = static_cast<int32_t>(reader.Read32());
    }
    else
    {
        pSelf = 0;
    }
}


std::optional<CompleteObjectLocator> ReadCompleteObjectorLocator(BinaryView *view, uint64_t address)
{
    auto coLocator = CompleteObjectLocator(view, address);
    uint64_t startAddr = view->GetOriginalImageBase();

    auto outsideSection = [&](uint64_t addr) {
        return view->GetSectionsAt(addr).empty();
    };

    if (coLocator.signature > 1)
        return std::nullopt;

    if (coLocator.signature == COL_SIG_REV1)
    {
        if (coLocator.pSelf + startAddr != address)
            return std::nullopt;

        // Relative addrs
        if (outsideSection(coLocator.pTypeDescriptor + startAddr))
            return std::nullopt;

        if (outsideSection(coLocator.pClassHierarchyDescriptor + startAddr))
            return std::nullopt;
    }
    else
    {
        // Absolute addrs
        if (outsideSection(coLocator.pTypeDescriptor))
            return std::nullopt;

        if (outsideSection(coLocator.pClassHierarchyDescriptor))
            return std::nullopt;
    }

    return coLocator;
}


Ref<Type> GetPMDType(BinaryView *view)
{
    auto typeId = Type::GenerateAutoTypeId(TYPE_SOURCE_MICROSOFT, QualifiedName("PMD"));
    Ref<Type> typeCache = view->GetTypeById(typeId);

    if (typeCache == nullptr)
    {
        Ref<Type> intType = Type::IntegerType(4, true);

        StructureBuilder pmdBuilder;
        pmdBuilder.AddMember(intType, "mdisp");
        pmdBuilder.AddMember(intType, "pdisp");
        pmdBuilder.AddMember(intType, "vdisp");

        view->DefineType(typeId, QualifiedName("_PMD"), TypeBuilder::StructureType(pmdBuilder.Finalize()).Finalize());
        typeCache = view->GetTypeById(typeId);
    }

    return typeCache;
}


Ref<Type> ClassHierarchyDescriptorType(BinaryView *view, BNPointerBaseType ptrBaseTy);

Ref<Type> BaseClassDescriptorType(BinaryView *view, BNPointerBaseType ptrBaseTy)
{
    auto typeId = Type::GenerateAutoTypeId(TYPE_SOURCE_MICROSOFT, QualifiedName("RTTIBaseClassDescriptor"));
    Ref<Type> typeCache = view->GetTypeById(typeId);

    if (typeCache == nullptr)
    {
        Ref<Architecture> arch = view->GetDefaultArchitecture();
        Ref<Type> uintType = Type::IntegerType(4, false);

        StructureBuilder baseClassDescriptorBuilder;
        // Would require creating a new type for every type descriptor length. Instead just use void*
        Ref<Type> pTypeDescType = TypeBuilder::PointerType(4, Type::VoidType())
                .SetPointerBase(ptrBaseTy, 0)
                .Finalize();
        baseClassDescriptorBuilder.AddMember(pTypeDescType, "pTypeDescriptor");
        baseClassDescriptorBuilder.AddMember(uintType, "numContainedBases");
        baseClassDescriptorBuilder.AddMember(GetPMDType(view), "where");
        Ref<Enumeration> attrEnum = EnumerationBuilder()
                .AddMemberWithValue("BCD_NOT_VISIBLE",         0x01)
                .AddMemberWithValue("BCD_AMBIGUOUS",           0x02)
                .AddMemberWithValue("BCD_PRIVORPROTBASE",      0x04)
                .AddMemberWithValue("BCD_PRIVORPROTINCOMPOBJ", 0x08)
                .AddMemberWithValue("BCD_VBOFCONTOBJ",         0x10)
                .AddMemberWithValue("BCD_NONPOLYMORPHIC",      0x20)
                .AddMemberWithValue("BCD_HASPCHD",             0x40)
                .Finalize();
        Ref<Type> attrType = Type::EnumerationType(arch, attrEnum, 4);
        baseClassDescriptorBuilder.AddMember(attrType, "attributes");
        Ref<Type> pClassDescType = TypeBuilder::PointerType(4, ClassHierarchyDescriptorType(view, ptrBaseTy))
                .SetPointerBase(ptrBaseTy, 0)
                .Finalize();
        baseClassDescriptorBuilder.AddMember(pClassDescType, "pClassDescriptor");

        view->DefineType(typeId, QualifiedName("_RTTIBaseClassDescriptor"),
                         TypeBuilder::StructureType(baseClassDescriptorBuilder.Finalize()).Finalize());
        typeCache = view->GetTypeById(typeId);
    }

    return typeCache;
}


Ref<Type> BaseClassArrayType(BinaryView *view, const uint64_t length, BNPointerBaseType ptrBaseTy)
{
    StructureBuilder baseClassArrayBuilder;
    Ref<Type> pBaseClassDescType = TypeBuilder::PointerType(4, BaseClassDescriptorType(view, ptrBaseTy))
            .SetPointerBase(ptrBaseTy, 0)
            .Finalize();
    baseClassArrayBuilder.AddMember(
        Type::ArrayType(pBaseClassDescType, length), "arrayOfBaseClassDescriptors");
    return TypeBuilder::StructureType(baseClassArrayBuilder.Finalize()).Finalize();
}


Ref<Type> ClassHierarchyDescriptorType(BinaryView *view, BNPointerBaseType ptrBaseTy)
{
    auto typeId = Type::GenerateAutoTypeId(TYPE_SOURCE_MICROSOFT, QualifiedName("RTTIClassHierarchyDescriptor"));
    Ref<Type> typeCache = view->GetTypeById(typeId);

    if (typeCache == nullptr)
    {
        Ref<Architecture> arch = view->GetDefaultArchitecture();
        Ref<Type> uintType = Type::IntegerType(4, false);

        StructureBuilder classHierarchyDescriptorBuilder;
        classHierarchyDescriptorBuilder.AddMember(uintType, "signature");
        Ref<Enumeration> attrEnum = EnumerationBuilder()
                .AddMemberWithValue("CHD_MULTINH",   0x01)
                .AddMemberWithValue("CHD_VIRTINH",   0x02)
                .AddMemberWithValue("CHD_AMBIGUOUS", 0x04)
                .Finalize();
        Ref<Type> attrType = Type::EnumerationType(arch, attrEnum, 4);
        classHierarchyDescriptorBuilder.AddMember(attrType, "attributes");
        classHierarchyDescriptorBuilder.AddMember(uintType, "numBaseClasses");
        Ref<Type> pBaseClassArrayType = TypeBuilder::PointerType(4, Type::VoidType())
                .SetPointerBase(ptrBaseTy, 0)
                .Finalize();
        classHierarchyDescriptorBuilder.AddMember(pBaseClassArrayType, "pBaseClassArray");

        view->DefineType(typeId, QualifiedName("_RTTIClassHierarchyDescriptor"),
                         TypeBuilder::StructureType(classHierarchyDescriptorBuilder.Finalize()).Finalize());

        typeCache = view->GetTypeById(typeId);
    }

    return typeCache;
}


Ref<Type> CompleteObjectLocator64Type(BinaryView *view)
{
    auto typeId = Type::GenerateAutoTypeId(TYPE_SOURCE_MICROSOFT, QualifiedName("RTTICompleteObjectLocator64"));
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
        Ref<Type> pClassHierarchyDescType = TypeBuilder::PointerType(
                    4, ClassHierarchyDescriptorType(view, RelativeToBinaryStartPointerBaseType))
                .SetPointerBase(RelativeToBinaryStartPointerBaseType, 0)
                .Finalize();
        completeObjectLocatorBuilder.AddMember(pClassHierarchyDescType, "pClassHierarchyDescriptor");
        Ref<Type> pSelfType = TypeBuilder::PointerType(4, Type::NamedType(view, typeId))
                .SetPointerBase(RelativeToBinaryStartPointerBaseType, 0)
                .Finalize();
        completeObjectLocatorBuilder.AddMember(pSelfType, "pSelf");

        view->DefineType(typeId, QualifiedName("_RTTICompleteObjectLocator"),
                         TypeBuilder::StructureType(completeObjectLocatorBuilder.Finalize()).Finalize());

        typeCache = view->GetTypeById(typeId);
    }

    return typeCache;
}


Ref<Type> CompleteObjectLocator32Type(BinaryView *view)
{
    auto typeId = Type::GenerateAutoTypeId(TYPE_SOURCE_MICROSOFT, QualifiedName("RTTICompleteObjectLocator32"));
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
                .Finalize();
        completeObjectLocatorBuilder.AddMember(pTypeDescType, "pTypeDescriptor");
        Ref<Type> pClassHierarchyDescType = TypeBuilder::PointerType(
                    4, ClassHierarchyDescriptorType(view, AbsolutePointerBaseType))
                .Finalize();
        completeObjectLocatorBuilder.AddMember(pClassHierarchyDescType, "pClassHierarchyDescriptor");

        view->DefineType(typeId, QualifiedName("_RTTICompleteObjectLocator"),
                         TypeBuilder::StructureType(completeObjectLocatorBuilder.Finalize()).Finalize());

        typeCache = view->GetTypeById(typeId);
    }

    return typeCache;
}


Ref<Type> TypeDescriptorType(BinaryView *view, uint64_t length)
{
    size_t addrSize = view->GetAddressSize();
    StructureBuilder typeDescriptorBuilder;
    typeDescriptorBuilder.AddMember(Type::PointerType(addrSize, Type::VoidType(), true), "pVFTable");
    typeDescriptorBuilder.AddMember(Type::PointerType(addrSize, Type::VoidType()), "spare");
    // Char array needs to be individually resized.
    typeDescriptorBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true, "char"), length), "name");
    return TypeBuilder::StructureType(typeDescriptorBuilder.Finalize()).Finalize();
}


std::vector<BaseClassInfo> MicrosoftRTTIProcessor::ProcessClassHierarchyDescriptor(uint64_t address, CompleteObjectLocator &coLocator, const ClassInfo &classInfo)
{
    auto startAddr = m_view->GetOriginalImageBase();
    auto resolveAddr = [&](const uint64_t relAddr) {
        return coLocator.signature == COL_SIG_REV1 ? startAddr + relAddr : relAddr;
    };

    auto ptrBaseTy = coLocator.signature ? RelativeToBinaryStartPointerBaseType : AbsolutePointerBaseType;

    auto classHierarchyDesc = ClassHierarchyDescriptor(m_view, address);
    auto classHierarchyDescName = fmt::format("{}::`RTTI Class Hierarchy Descriptor'", classInfo.className);
    m_view->DefineAutoSymbol(new Symbol{DataSymbol, classHierarchyDescName, address});
    m_view->DefineDataVariable(address,
                            Confidence(ClassHierarchyDescriptorType(m_view, ptrBaseTy), RTTI_CONFIDENCE));

    auto baseClassArrayAddr = resolveAddr(classHierarchyDesc.pBaseClassArray);
    auto baseClassArray = BaseClassArray(m_view, baseClassArrayAddr, classHierarchyDesc.numBaseClasses);
    auto baseClassArrayName = fmt::format("{}::`RTTI Base Class Array'", classInfo.className);
    m_view->DefineAutoSymbol(new Symbol{DataSymbol, baseClassArrayName, baseClassArrayAddr});
    m_view->DefineDataVariable(baseClassArrayAddr,
                            Confidence(BaseClassArrayType(m_view, baseClassArray.length, ptrBaseTy),
                                        RTTI_CONFIDENCE));

    std::vector<BaseClassInfo> baseClasses = {};
    for (auto pBaseClassDescAddr: baseClassArray.descriptors)
    {
        auto baseClassDescAddr = resolveAddr(pBaseClassDescAddr);
        auto baseClassDesc = BaseClassDescriptor(m_view, baseClassDescAddr);

        auto baseClassTypeDescAddr = resolveAddr(baseClassDesc.pTypeDescriptor);
        auto baseClassTypeDesc = TypeDescriptor(m_view, baseClassTypeDescAddr);
        auto baseClassName = DemangleNameMS(m_view, allowMangledClassNames, baseClassTypeDesc.name);
        if (!baseClassName.has_value())
        {
            m_logger->LogWarn("Skipping BaseClassDescriptor with mangled name %llx", baseClassTypeDescAddr);
            continue;
        }

        BaseClassInfo baseClassInfo = {baseClassName.value(), (uint64_t)baseClassDesc.where_mdisp};

        auto baseClassDescName = fmt::format("{}::`RTTI Base Class Descriptor at ({},{},{},{})", baseClassInfo.className,
                                            baseClassDesc.where_mdisp, baseClassDesc.where_pdisp,
                                            baseClassDesc.where_vdisp, baseClassDesc.attributes);
        m_view->DefineAutoSymbol(new Symbol{DataSymbol, baseClassDescName, baseClassDescAddr});
        m_view->DefineDataVariable(baseClassDescAddr,
                                Confidence(BaseClassDescriptorType(m_view, ptrBaseTy), RTTI_CONFIDENCE));

        auto baseClassTypeDescSymName = fmt::format("class {} `RTTI Type Descriptor'", baseClassInfo.className);
        m_view->DefineAutoSymbol(new Symbol{DataSymbol, baseClassTypeDescSymName, baseClassTypeDescAddr});
        m_view->DefineDataVariable(baseClassTypeDescAddr,
                                Confidence(TypeDescriptorType(m_view, baseClassTypeDesc.name.length()), RTTI_CONFIDENCE));

        // If we are not dealing with are own class we should add it as a base class.
        if (baseClassDesc.where_mdisp != 0 || baseClassInfo.className != classInfo.className)
        {
            if (baseClassDesc.attributes & BCD_HASPCHD) {
                baseClasses.emplace_back(baseClassInfo);
            }
        }
    }

    return baseClasses;
}

std::optional<ClassInfo> MicrosoftRTTIProcessor::ProcessRTTI(uint64_t coLocatorAddr)
{
    auto coLocator = ReadCompleteObjectorLocator(m_view, coLocatorAddr);
    if (!coLocator.has_value())
        return std::nullopt;

    auto startAddr = m_view->GetOriginalImageBase();
    auto resolveAddr = [&](const uint64_t relAddr) {
        return coLocator->signature == COL_SIG_REV1 ? startAddr + relAddr : relAddr;
    };

    // Get type descriptor then check to see if the class name was demangled.
    auto typeDescAddr = resolveAddr(coLocator->pTypeDescriptor);
    auto typeDesc = TypeDescriptor(m_view, typeDescAddr);
    auto className = DemangleNameMS(m_view, allowMangledClassNames, typeDesc.name);
    if (!className.has_value())
        return std::nullopt;

    // If the className is empty we will change it to the address, this is to fix type clobbering.
    if (className->empty())
    {
        if (!allowAnonymousClassNames)
        {
            m_logger->LogDebug("Skipping CompleteObjectorLocator with anonymous name %llx", coLocatorAddr);
            return std::nullopt;
        }
        className = fmt::format("anonymous_{:#x}", coLocatorAddr);
    }

    auto classInfo = ClassInfo{RTTIProcessorType::Microsoft, className.value()};

    auto classHierarchyDescAddr = resolveAddr(coLocator->pClassHierarchyDescriptor);
    classInfo.baseClasses = ProcessClassHierarchyDescriptor(classHierarchyDescAddr, coLocator.value(), classInfo);

    // Locate the current base class if we are in one.
    std::optional<BaseClassInfo> currentBaseClass;
    if (coLocator->offset > 0)
    {
        for (const auto &baseClassInfo: classInfo.baseClasses)
        {
            if (baseClassInfo.className != classInfo.className
                && baseClassInfo.offset == coLocator->offset)
            {
                currentBaseClass = baseClassInfo;
                break;
            }
        }
    }

    auto typeDescSymName = fmt::format("class {} `RTTI Type Descriptor'", classInfo.className);
    m_view->DefineAutoSymbol(new Symbol{DataSymbol, typeDescSymName, typeDescAddr});
    m_view->DefineDataVariable(typeDescAddr,
                               Confidence(TypeDescriptorType(m_view, typeDesc.name.length()), RTTI_CONFIDENCE));

    auto coLocatorName = fmt::format("{}::`RTTI Complete Object Locator'", className.value());
    if (currentBaseClass.has_value())
        coLocatorName += fmt::format("{{for `{}'}}", currentBaseClass->className);

    m_view->DefineAutoSymbol(new Symbol{DataSymbol, coLocatorName, coLocatorAddr});
    if (coLocator->signature == COL_SIG_REV1)
        m_view->DefineDataVariable(coLocatorAddr, Confidence(CompleteObjectLocator64Type(m_view), RTTI_CONFIDENCE));
    else
        m_view->DefineDataVariable(coLocatorAddr, Confidence(CompleteObjectLocator32Type(m_view), RTTI_CONFIDENCE));

    return classInfo;
}


std::optional<VirtualFunctionTableInfo> MicrosoftRTTIProcessor::ProcessVFT(uint64_t vftAddr, ClassInfo &classInfo, std::optional<BaseClassInfo> baseClassInfo)
{
    VirtualFunctionTableInfo vftInfo = {vftAddr};
    // Gather all virtual functions
    BinaryReader reader = BinaryReader(m_view);
    reader.Seek(vftAddr);
    // Virtual functions and the analysis object of it, if it exists.
    std::vector<std::pair<uint64_t, std::optional<Ref<Function>>>> virtualFunctions = {};
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
            // TODO: Is likely a function check here?
            m_logger->LogDebug("Discovered function from virtual function table... %llx", vFuncAddr);
            auto vFunc = m_view->AddFunctionForAnalysis(m_view->GetDefaultPlatform(), vFuncAddr, true);
            virtualFunctions.emplace_back(vFuncAddr, vFunc ? std::optional(vFunc) : std::nullopt);
        }
        else
        {
            // Only ever add one function.
            virtualFunctions.emplace_back(vFuncAddr, funcs.front());
        }
    }

    if (virtualFunctions.empty())
    {
        m_logger->LogDebug("Skipping empty virtual function table... %llx", vftAddr);
        return std::nullopt;
    }

    for (auto &[vFuncAddr, _]: virtualFunctions)
        vftInfo.virtualFunctions.emplace_back(VirtualFunctionInfo{vFuncAddr});

    // Create virtual function table type
    auto vftTypeName = fmt::format("{}::VTable", classInfo.className);
    if (baseClassInfo.has_value())
    {
        // TODO: What is the correct form for the name?
        vftTypeName = fmt::format("{}::{}", baseClassInfo->className, vftTypeName);
    }
    // TODO: Hack the debug type id is used here to allow the PDB type (debug info) to overwrite the RTTI vtable type.
    auto typeId = Type::GenerateAutoDebugTypeId(vftTypeName);
    Ref<Type> vftType = m_view->GetTypeById(typeId);

    if (vftType == nullptr)
    {
        size_t addrSize = m_view->GetAddressSize();
        StructureBuilder vftBuilder = {};
        vftBuilder.SetPropagateDataVariableReferences(true);
        size_t vFuncIdx = 0;

        // Until https://github.com/Vector35/binaryninja-api/issues/5982 is fixed
        auto vftSize = virtualFunctions.size() * addrSize;
        vftBuilder.SetWidth(vftSize);
        
        if (baseClassInfo.has_value() && baseClassInfo->vft.has_value())
        {
            if (baseClassInfo->vft->virtualFunctions.size() <= virtualFunctions.size())
            {
                // Adjust the current vFunc index to the end of the shared vFuncs.
                vFuncIdx = baseClassInfo->vft->virtualFunctions.size();
                virtualFunctions.erase(virtualFunctions.begin(), virtualFunctions.begin() + vFuncIdx);
                // We should set the vtable as a base class so that xrefs are propagated (among other things).
                // NOTE: this means that `this` params will be assumed pre-adjusted, this is normally fine assuming type propagation
                // NOTE: never occurs on the vft types. Other-wise we need to change this.
                auto baseVftTypeName = fmt::format("{}::VTable", baseClassInfo->className);
                NamedTypeReferenceBuilder baseVftNTR;
                baseVftNTR.SetName(baseVftTypeName);
                // Width is unresolved here so that we can keep non-base vfuncs un-inherited.
                auto baseVftSize = vFuncIdx * addrSize;
                vftBuilder.SetBaseStructures({ BaseStructure(baseVftNTR.Finalize(), 0, baseVftSize) });
            }
            else
            {
                LogWarn("Skipping adjustments for base VFT with more functions than sub VFT... %llx", vftAddr);
            }
        }
        
        for (auto &&[_, vFunc]: virtualFunctions)
        {
            auto vFuncName = fmt::format("vFunc_{}", vFuncIdx);
            if (vFunc.has_value())
            {
                // If we have a better name, use it.
                auto vFuncObj = vFunc.value();
                auto vFuncSymName = vFuncObj->GetSymbol()->GetShortName();
                if (vFuncSymName.compare(0, 4, "sub_") != 0)
                    vFuncName = vFuncObj->GetSymbol()->GetShortName();
                // MyClass::func -> func
                std::size_t pos = vFuncName.rfind("::");
                if (pos != std::string::npos)
                    vFuncName = vFuncName.substr(pos + 2);
            }

            // NOTE: The analyzed function type might not be available here.
            auto vFuncOffset = vFuncIdx * addrSize;
            // We have access to a backing function type, use it, otherwise void!
            auto vFuncType = vFunc.has_value() ? vFunc.value()->GetType() : Type::VoidType();
            vftBuilder.AddMemberAtOffset(
                Type::PointerType(addrSize, vFuncType, true), vFuncName, vFuncOffset);
            vFuncIdx++;
        }

        // TODO: Hack, we have a base class at 0 we are defining, meaning we never get the MyClass::VTable
        // TODO: Only the MyBase::MyClass::VTable, and people who reference this type dont know that the appropriate type is the
        // TODO: MyBase::MyClass::VTable, we should create a fake vtable for this type to redirect to the correct 0 offset base class type.
        if (baseClassInfo.has_value() && baseClassInfo->offset == 0)
        {
            NamedTypeReferenceBuilder namedTypeRef;
            namedTypeRef.SetName(vftTypeName);
            namedTypeRef.SetTypeId(typeId);
            auto rootRedirectType = Confidence(Type::NamedType(namedTypeRef.Finalize()), RTTI_CONFIDENCE);
            auto rootRedirectName = fmt::format("{}::VTable", classInfo.className);
            auto redirectTypeId = Type::GenerateAutoDebugTypeId(rootRedirectName);
            // This will now create the redirect type MyClass::VTable for uninformed analysis to use.
            // MyClass -> MyBase::MyClass::VTable (when MyBase offset is 0).
            m_view->DefineType(redirectTypeId, rootRedirectName, rootRedirectType);
        }
        m_view->DefineType(typeId, vftTypeName,
                           Confidence(TypeBuilder::StructureType(vftBuilder.Finalize()).Finalize(), RTTI_CONFIDENCE));
    }

    auto vftName = fmt::format("{}::`vftable'", classInfo.className);
    if (baseClassInfo.has_value())
        vftName += fmt::format("{{for `{}'}}", baseClassInfo->className);
    m_view->DefineAutoSymbol(new Symbol{DataSymbol, vftName, vftAddr});
    m_view->DefineDataVariable(vftAddr, Confidence(Type::NamedType(m_view, vftTypeName), RTTI_CONFIDENCE));
    return vftInfo;
}


MicrosoftRTTIProcessor::MicrosoftRTTIProcessor(const Ref<BinaryView> &view, bool useMangled, bool checkRData, bool vftSweep, bool allowAnonymous)
{
    m_view = view;
    m_logger = new Logger("Microsoft RTTI");
    allowMangledClassNames = useMangled;
    allowAnonymousClassNames = allowAnonymous;
    checkWritableRData = checkRData;
    m_classInfo = {};
    virtualFunctionTableSweep = vftSweep;
    auto metadata = view->QueryMetadata(VIEW_METADATA_RTTI);
    if (metadata != nullptr)
    {
        // Load in metadata to the processor.
        DeserializedMetadata(RTTIProcessorType::Microsoft, metadata);
    }
}


void MicrosoftRTTIProcessor::ProcessRTTI()
{
    auto bgTask = new BackgroundTask("Scanning for Microsoft RTTI...", true);
    auto start_time = std::chrono::high_resolution_clock::now();
    uint64_t startAddr = m_view->GetOriginalImageBase();
    uint64_t endAddr = m_view->GetEnd();
    BinaryReader optReader = BinaryReader(m_view);
    auto addrSize = m_view->GetAddressSize();

    auto scan = [&](const Ref<Segment> &segment) {
        for (uint64_t coLocatorAddr = segment->GetStart(); coLocatorAddr < segment->GetEnd() - 0x18;
             coLocatorAddr += addrSize)
        {
            if (bgTask->IsCancelled())
                break;
            optReader.Seek(coLocatorAddr);
            uint32_t sigVal = optReader.Read32();
            if (sigVal == COL_SIG_REV1)
            {
                // Check for self reference
                optReader.SeekRelative(16);
                if (optReader.Read32() == coLocatorAddr - startAddr)
                {
                    if (auto classInfo = ProcessRTTI(coLocatorAddr))
                        m_classInfo[coLocatorAddr] = classInfo.value();
                }
            }
            else if (sigVal == COL_SIG_REV0)
            {
                // Check ?AV
                optReader.SeekRelative(8);
                uint64_t typeDescNameAddr = optReader.Read32() + 8;
                if (typeDescNameAddr > startAddr && typeDescNameAddr < endAddr)
                {
                    // Make sure we do not read across segment boundary.
                    auto typeDescSegment = m_view->GetSegmentAt(typeDescNameAddr);
                    if (typeDescSegment != nullptr && typeDescSegment->GetEnd() - typeDescNameAddr > 4)
                    {
                        optReader.Seek(typeDescNameAddr);
                        auto typeDescNameStart = optReader.ReadString(4);
                        if (typeDescNameStart == ".?AV" || typeDescNameStart == ".?AU" || typeDescNameStart == ".?AW")
                        {
                            if (auto classInfo = ProcessRTTI(coLocatorAddr))
                                m_classInfo[coLocatorAddr] = classInfo.value();
                        }
                    }
                }
            }
        }
    };

    // Scan data sections for colocators.
    auto rdataSection = m_view->GetSectionByName(".rdata");
    for (const Ref<Segment> &segment: m_view->GetSegments())
    {
        if (segment->GetFlags() == (SegmentReadable | SegmentContainsData))
        {
            m_logger->LogDebug("Attempting to find RTTI in segment %llx", segment->GetStart());
            scan(segment);
        }
        else if (checkWritableRData && rdataSection && rdataSection->GetStart() == segment->GetStart())
        {
            m_logger->LogDebug("Attempting to find RTTI in writable rdata segment %llx",
                               segment->GetStart());
            scan(segment);
        }
    }

    bgTask->Finish();
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_time = end_time - start_time;
    m_logger->LogDebug("ProcessRTTI took %f seconds", elapsed_time.count());
}


void MicrosoftRTTIProcessor::ProcessVFT()
{
    auto bgTask = new BackgroundTask("Scanning for Microsoft RTTI...", true);
    std::map<uint64_t, uint64_t> vftMap = {};
    std::map<uint64_t, std::optional<VirtualFunctionTableInfo>> vftFinishedMap = {};
    auto start_time = std::chrono::high_resolution_clock::now();
    for (auto &[coLocatorAddr, classInfo]: m_classInfo)
    {
        for (auto &ref: m_view->GetDataReferences(coLocatorAddr))
        {
            auto vftAddr = ref + m_view->GetAddressSize();
            vftMap[coLocatorAddr] = vftAddr;
        }
    }

    if (virtualFunctionTableSweep)
    {
        BinaryReader optReader = BinaryReader(m_view);
        auto addrSize = m_view->GetAddressSize();
        auto scan = [&](const Ref<Segment> &segment) {
            uint64_t startAddr = segment->GetStart();
            uint64_t endAddr = segment->GetEnd();
            for (uint64_t vtableAddr = startAddr; vtableAddr < endAddr - 0x18; vtableAddr += addrSize)
            {
                if (bgTask->IsCancelled())
                    break;
                optReader.Seek(vtableAddr);
                uint64_t coLocatorAddr = optReader.ReadPointer();
                auto coLocator = m_classInfo.find(coLocatorAddr);
                if (coLocator == m_classInfo.end())
                    continue;
                // Found a vtable reference to colocator.
                vftMap[coLocatorAddr] = vtableAddr + addrSize;
            }
        };

        // Scan data sections for virtual function tables.
        auto rdataSection = m_view->GetSectionByName(".rdata");
        for (const Ref<Segment> &segment: m_view->GetSegments())
        {
            if (segment->GetFlags() == (SegmentReadable | SegmentContainsData))
            {
                m_logger->LogDebug("Attempting to find VirtualFunctionTables in segment %llx", segment->GetStart());
                scan(segment);
            }
            else if (checkWritableRData && rdataSection && rdataSection->GetStart() == segment->GetStart())
            {
                m_logger->LogDebug("Attempting to find VirtualFunctionTables in writable rdata segment %llx",
                                   segment->GetStart());
                scan(segment);
            }
        }
    }

    auto GetCachedVFTInfo = [&](uint64_t vftAddr, ClassInfo& classInfo) -> std::optional<VirtualFunctionTableInfo> {
        // Check in the cache so that we don't process vfts more than once.
        auto cachedVftInfo = vftFinishedMap.find(vftAddr);
        if (cachedVftInfo != vftFinishedMap.end())
            return cachedVftInfo->second;

        // Get the appropriate base class if there is one by reading the colocator.
        BinaryReader reader = BinaryReader(m_view);
        reader.Seek(vftAddr - m_view->GetAddressSize());
        auto coLocatorAddr = reader.ReadPointer();
        auto coLocator = ReadCompleteObjectorLocator(m_view, coLocatorAddr);
        // TODO: This should always be valid!
        if (!coLocator.has_value())
            return std::nullopt;

        std::optional<BaseClassInfo> baseClassInfo;
        for (const auto& base: classInfo.baseClasses)
        {
            if (base.offset == coLocator->offset && base.className != classInfo.className)
            {
                // Take the first to match the offset with a different name from the class.
                baseClassInfo = base;
                break;
            }
        }

        auto vftInfo = ProcessVFT(vftAddr, classInfo, baseClassInfo);
        vftFinishedMap[vftAddr] = vftInfo;
        return vftInfo;
    };

    std::function<void(uint64_t)> ProcessClassAndBases = [&](uint64_t coLocatorAddr) -> void {
        auto& classInfo = m_classInfo[coLocatorAddr];

        // Process all relevant base classes first.
        // Otherwise, when we process this class we won't have the base vft available if needed.
        for (auto& baseInfo : classInfo.baseClasses)
        {
            for (auto& [baseCoLocAddr, baseClassInfo] : m_classInfo)
            {
                if (baseClassInfo.className == baseInfo.className)
                {
                    uint64_t baseVftAddr = vftMap[baseCoLocAddr];
                    // Recurse into the bases bases.
                    ProcessClassAndBases(baseCoLocAddr);

                    // Fetch the VFT info for the base class and store it.
                    if (auto baseVftInfo = GetCachedVFTInfo(baseVftAddr, baseClassInfo))
                    {
                        baseInfo.vft = baseVftInfo.value();
                        break;
                    }
                }
            }
        }

        // Process the vtable for the current class.
        // By this point all base classes should already exist, along with their type.
        uint64_t vftAddr = vftMap[coLocatorAddr];
        if (auto vftInfo = GetCachedVFTInfo(vftAddr, classInfo))
            classInfo.vft = vftInfo.value();
    };
    
    for (const auto &[coLocatorAddr, _]: vftMap)
        ProcessClassAndBases(coLocatorAddr);

    bgTask->Finish();
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_time = end_time - start_time;
    m_logger->LogDebug("ProcessVFT took %f seconds", elapsed_time.count());
}