#include "itanium.h"

using namespace BinaryNinja;
using namespace BinaryNinja::RTTI;
using namespace BinaryNinja::RTTI::Itanium;

// TODO: Need to add the boiler plate stuff
// TODO: Can we find the object offset for the vtable entry?
// TODO: Itanium doesnt really say anything about the sizing of these fields, i assume they are all u32 for thje most part.

constexpr const char *TYPE_SOURCE_ITANIUM = "rtti_itanium";

TypeInfo::TypeInfo(BinaryView *view, uint64_t address)
{
    BinaryReader reader = BinaryReader(view);
    reader.Seek(address);
    base = reader.ReadPointer();
    auto typeNameAddr = reader.ReadPointer();
    reader.Seek(typeNameAddr);
    type_name = reader.ReadCString(512);
}


SIClassTypeInfo::SIClassTypeInfo(BinaryView *view, uint64_t address) : ClassTypeInfo(view, address)
{
    BinaryReader reader = BinaryReader(view);
    // TODO: Manually seeking to the offset is ugly.
    reader.Seek(address + 0x10);
    base_type = reader.ReadPointer();
}


BaseClassTypeInfo::BaseClassTypeInfo(BinaryView *view, uint64_t address)
{
    BinaryReader reader = BinaryReader(view);
    reader.Seek(address);
    base_type = reader.ReadPointer();
    offset_flags = reader.Read32();
    // TODO: Test this...
    offset_flags_masks = static_cast<OffsetFlagsMasks>(reader.Read32());
}


VMIClassTypeInfo::VMIClassTypeInfo(BinaryView *view, uint64_t address) : ClassTypeInfo(view, address)
{
    BinaryReader reader = BinaryReader(view);
    // TODO: Manually seeking to the offset is ugly.
    reader.Seek(address + 0x10);
    flags = reader.Read32();
    base_count = reader.Read32();
    base_info = {};
    for (size_t i = 1; i < base_count; i++)
    {
        // TODO: Verify this is correct.
        uint64_t currentBaseAddr = reader.GetOffset();
        base_info.emplace_back(view, reader.GetOffset());
        reader.Seek(currentBaseAddr + 12);
    }
}


Ref<Type> TypeInfoType(BinaryView *view)
{
    auto typeId = Type::GenerateAutoTypeId(TYPE_SOURCE_ITANIUM, QualifiedName("TypeInfo"));
    Ref<Type> typeCache = view->GetTypeById(typeId);

    if (typeCache == nullptr)
    {
        Ref<Architecture> arch = view->GetDefaultArchitecture();

        StructureBuilder structureBuilder;
        Ref<Type> pBaseType = Type::PointerType(arch, Type::VoidType());
        structureBuilder.AddMember(pBaseType, "__base");
        Ref<Type> pTypeNameType = Type::PointerType(arch, Type::IntegerType(1, true, "char"));
        structureBuilder.AddMember(pTypeNameType, "__type_name");

        Ref<Type> structureType = TypeBuilder::StructureType(structureBuilder.Finalize()).Finalize();
        // TODO: std::type_info or __cxxabiv1::__type_info ?
        view->DefineType(typeId, QualifiedName("std::type_info"), structureType);

        typeCache = view->GetTypeById(typeId);
    }

    return typeCache;
}


Ref<Type> ClassTypeInfoType(BinaryView *view)
{
    auto typeId = Type::GenerateAutoTypeId(TYPE_SOURCE_ITANIUM, QualifiedName("ClassTypeInfo"));
    Ref<Type> typeCache = view->GetTypeById(typeId);

    if (typeCache == nullptr)
    {
        StructureBuilder structureBuilder;
        BaseStructure typeInfoBase = BaseStructure(TypeInfoType(view), 0);
        structureBuilder.SetBaseStructures({typeInfoBase});
        // TODO: This exists because if you have no members but a base struct things get screwy.
        structureBuilder.SetWidth(0x10);

        Ref<Type> structureType = TypeBuilder::StructureType(structureBuilder.Finalize()).Finalize();
        view->DefineType(typeId, QualifiedName("__cxxabiv1::__class_type_info"), structureType);

        typeCache = view->GetTypeById(typeId);
    }

    return typeCache;
}

Ref<Type> SIClassTypeInfoType(BinaryView *view)
{
    auto typeId = Type::GenerateAutoTypeId(TYPE_SOURCE_ITANIUM, QualifiedName("SIClassTypeInfo"));
    Ref<Type> typeCache = view->GetTypeById(typeId);

    if (typeCache == nullptr)
    {
        Ref<Architecture> arch = view->GetDefaultArchitecture();

        StructureBuilder structureBuilder;
        Ref<Type> pBaseType = Type::PointerType(arch, Type::VoidType());
        structureBuilder.AddMemberAtOffset(pBaseType, "__base_type", 0x10);
        BaseStructure classTypeInfoBase = BaseStructure(ClassTypeInfoType(view), 0);
        structureBuilder.SetBaseStructures({classTypeInfoBase});

        Ref<Type> structureType = TypeBuilder::StructureType(structureBuilder.Finalize()).Finalize();
        view->DefineType(typeId, QualifiedName("__cxxabiv1::__si_class_type_info"), structureType);

        typeCache = view->GetTypeById(typeId);
    }

    return typeCache;
}


Ref<Type> OffsetFlagsMasksType(BinaryView *view)
{
    auto typeId = Type::GenerateAutoTypeId(TYPE_SOURCE_ITANIUM, QualifiedName("OffsetFlagsMasks"));
    Ref<Type> typeCache = view->GetTypeById(typeId);

    if (typeCache == nullptr)
    {
        Ref<Architecture> arch = view->GetDefaultArchitecture();
        Ref<Type> uintType = Type::IntegerType(4, false);

        EnumerationBuilder enumerationBuilder;
        enumerationBuilder.AddMemberWithValue("__virtual_mask", 0x1);
        enumerationBuilder.AddMemberWithValue("__public_mask", 0x2);
        enumerationBuilder.AddMemberWithValue("__offset_shift", 0x8);

        Ref<Type> enumerationType = TypeBuilder::EnumerationType(arch, enumerationBuilder.Finalize()).Finalize();
        view->DefineType(typeId, QualifiedName("__cxxabiv1::__offset_flags_masks"), enumerationType);

        typeCache = view->GetTypeById(typeId);
    }

    return typeCache;
}


Ref<Type> BaseClassTypeInfoType(BinaryView *view)
{
    auto typeId = Type::GenerateAutoTypeId(TYPE_SOURCE_ITANIUM, QualifiedName("BaseClassTypeInfo"));
    Ref<Type> typeCache = view->GetTypeById(typeId);

    if (typeCache == nullptr)
    {
        Ref<Architecture> arch = view->GetDefaultArchitecture();
        Ref<Type> uintType = Type::IntegerType(4, false);

        StructureBuilder structureBuilder;
        Ref<Type> pBaseType = Type::PointerType(arch, Type::VoidType());
        structureBuilder.AddMember(pBaseType, "__base_type");
        structureBuilder.AddMember(uintType, "__offset_flags");
        structureBuilder.AddMember(OffsetFlagsMasksType(view), "__offset_flags_masks");

        Ref<Type> structureType = TypeBuilder::StructureType(structureBuilder.Finalize()).Finalize();
        view->DefineType(typeId, QualifiedName("__cxxabiv1::__base_class_type_info"), structureType);

        typeCache = view->GetTypeById(typeId);
    }

    return typeCache;
}


Ref<Type> VMIClassTypeInfoType(BinaryView *view, int baseCount)
{
    Ref<Architecture> arch = view->GetDefaultArchitecture();
    Ref<Type> uintType = Type::IntegerType(4, false);

    StructureBuilder structureBuilder;
    structureBuilder.AddMemberAtOffset(uintType, "__flags", 0x10);
    structureBuilder.AddMemberAtOffset(uintType, "__base_count", 0x14);
    Ref<Type> baseInfoType = Type::ArrayType(BaseClassTypeInfoType(view), baseCount);
    structureBuilder.AddMemberAtOffset(baseInfoType, "__base_info", 0x18);
    BaseStructure classTypeInfoBase = BaseStructure(ClassTypeInfoType(view), 0);
    structureBuilder.SetBaseStructures({classTypeInfoBase});

    return TypeBuilder::StructureType(structureBuilder.Finalize()).Finalize();
}


std::optional<TypeInfoVariant> ReadTypeInfoVariant(BinaryView *view, uint64_t objectAddr)
{
    auto typeInfo = TypeInfo(view, objectAddr);
    
    // TODO: What if there is no symbol?
    // If there is a symbol at objectAddr pointing to a symbol starting with "vtable for __cxxabiv1"
    auto baseSym = view->GetSymbolByAddress(typeInfo.base);
    if (baseSym == nullptr)
    {
        // Check relocation at objectAddr for symbol
        for (const auto& r : view->GetRelocationsAt(objectAddr))
            if (auto relocSym = r->GetSymbol())
                baseSym = relocSym;
        if (baseSym == nullptr)
            return std::nullopt;
    }
    if (baseSym->GetType() != ExternalSymbol)
        return std::nullopt;
    auto baseSymName = baseSym->GetShortName();
    if (baseSymName.find("__cxxabiv1") != std::string::npos)
    {
        // symbol takes the form of `abi::base_name`
        auto baseTyStartPos = baseSymName.find("::");
        if (baseTyStartPos != std::string::npos)
            baseSymName = baseSymName.substr(baseTyStartPos + 2);

        if (baseSymName == "__class_type_info")
            return TIVClass;
        if (baseSymName == "__si_class_type_info")
            return TIVSIClass;
        if (baseSymName == "__vmi_class_type_info")
            return TIVVMIClass;   
    }

    return std::nullopt;
}


std::optional<ClassInfo> ItaniumRTTIProcessor::ProcessRTTI(uint64_t objectAddr)
{
    // TODO: You cant get subobject offsets from rtti, its stored above this ptr in vtable.
    // Get object as type info then check to see if it's valid.
    auto typeInfoVariant = ReadTypeInfoVariant(m_view, objectAddr);
    if (!typeInfoVariant.has_value())
        return std::nullopt;

    auto typeInfo = TypeInfo(m_view, objectAddr);
    auto className = DemangleNameItanium(m_view, allowMangledClassNames, typeInfo.type_name);
    if (!className.has_value())
        return std::nullopt;
    auto classInfo = ClassInfo{RTTIProcessorType::Itanium, className.value()};

    auto typeInfoName = fmt::format("_typeinfo_for_{}", classInfo.className);
    auto typeInfoSymbol = m_view->GetSymbolByAddress(objectAddr);
    if (typeInfoSymbol != nullptr)
        m_view->UndefineAutoSymbol(typeInfoSymbol);
    m_view->DefineAutoSymbol(new Symbol{DataSymbol, typeInfoName, objectAddr});

    if (typeInfoVariant == TIVSIClass)
    {
        // Read the base class.
        auto siClassTypeInfo = SIClassTypeInfo(m_view, objectAddr);
        auto subTypeInfoVariant = ReadTypeInfoVariant(m_view, siClassTypeInfo.base_type);
        if (!subTypeInfoVariant.has_value())
            return std::nullopt;
        auto subTypeInfo = TypeInfo(m_view, siClassTypeInfo.base_type);
        // Demangle base class name and set
        auto baseClassName = DemangleNameItanium(m_view, allowMangledClassNames, subTypeInfo.type_name);
        if (!baseClassName.has_value())
        {
            m_logger->LogWarn("Skipping base class with mangled name %llx", siClassTypeInfo.base_type);
            return std::nullopt;
        }
        classInfo.baseClassName = baseClassName;
        // NOTE: The base class offset is not able to be resolved here.
        // NOTE: To resolve the base class offset you must go to the vtable.
        m_view->DefineDataVariable(objectAddr, Confidence(SIClassTypeInfoType(m_view), 255));
    }
    else if (typeInfoVariant == TIVVMIClass)
    {
        // TODO: Read multiple base classes.
        auto vmiClassTypeInfo = VMIClassTypeInfo(m_view, objectAddr);
        m_view->DefineDataVariable(objectAddr, Confidence(VMIClassTypeInfoType(m_view, vmiClassTypeInfo.base_count), 255));
    }
    else
    {
        // auto classTypeInfo = ClassTypeInfo(m_view, objectAddr);
        m_view->DefineDataVariable(objectAddr, Confidence(ClassTypeInfoType(m_view), 255));
    }

    return classInfo;
}


std::optional<VirtualFunctionTableInfo> ItaniumRTTIProcessor::ProcessVFT(uint64_t vftAddr, ClassInfo &classInfo)
{
    VirtualFunctionTableInfo vftInfo = {vftAddr};
    BinaryReader reader = BinaryReader(m_view);
    reader.Seek(vftAddr);
    // Gather all virtual functions
    std::vector<Ref<Function> > virtualFunctions = {};
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
            // TODO: Sometimes vFunc idx will be zeroed.
            // TODO: Is likely a function check here?
            m_logger->LogDebug("Discovered function from virtual function table... %llx", vFuncAddr);
            auto vFunc = m_view->AddFunctionForAnalysis(m_view->GetDefaultPlatform(), vFuncAddr, true);
            funcs.emplace_back(vFunc);
        }
        // Only ever add one function.
        virtualFunctions.emplace_back(funcs.front());
    }

    if (virtualFunctions.empty())
    {
        m_logger->LogDebug("Skipping empty virtual function table... %llx", vftAddr);
        return std::nullopt;
    }

    // All vft verification has been done, we can write the classOffset now.
    if (classInfo.baseClassName.has_value() && !classInfo.classOffset.has_value())
    {
        // Because we have this we _need_ to have the adjustment stuff.
        // NOTE: We assume two 0x4 ints with the first being what we want.
        // NOTE: This is where we actually classOffset is pulled.
        reader.Seek(vftAddr - 0x10);
        auto adjustmentOffset = static_cast<int32_t>(reader.Read32());
        auto _what = static_cast<int32_t>(reader.Read32());
        uint64_t classOffset = std::abs(adjustmentOffset);
        classInfo.classOffset = classOffset;
    }


    for (auto &func: virtualFunctions)
        vftInfo.virtualFunctions.emplace_back(VirtualFunctionInfo{func->GetStart()});

    // Create virtual function table type
    auto vftTypeName = fmt::format("{}::VTable", classInfo.className);
    if (classInfo.baseClassName.has_value())
    {
        // TODO: What is the correct form for the name?
        vftTypeName = fmt::format("{}::{}", classInfo.baseClassName.value(), vftTypeName);
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

        // TODO: Until https://github.com/Vector35/binaryninja-api/issues/5982 is fixed
        auto vftSize = virtualFunctions.size() * addrSize;
        vftBuilder.SetWidth(vftSize);

        if (auto baseVft = classInfo.baseVft)
        {
            if (baseVft->virtualFunctions.size() <= virtualFunctions.size())
            {
                // Adjust the current vFunc index to the end of the shared vFuncs.
                vFuncIdx = baseVft->virtualFunctions.size();
                virtualFunctions.erase(virtualFunctions.begin(), virtualFunctions.begin() + vFuncIdx);
                // We should set the vtable as a base class so that xrefs are propagated (among other things).
                // NOTE: this means that `this` params will be assumed pre-adjusted, this is normally fine assuming type propagation
                // NOTE: never occurs on the vft types. Other-wise we need to change this.
                auto baseVftTypeName = fmt::format("{}::VTable", classInfo.baseClassName.value());
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

        for (auto &&vFunc: virtualFunctions)
        {
            auto vFuncName = fmt::format("vFunc_{}", vFuncIdx);
            // If we have a better name, use it.
            auto vFuncSymName = vFunc->GetSymbol()->GetShortName();
            if (vFuncSymName.compare(0, 4, "sub_") != 0)
                vFuncName = vFunc->GetSymbol()->GetShortName();
            // MyClass::func -> func
            std::size_t pos = vFuncName.rfind("::");
            if (pos != std::string::npos)
                vFuncName = vFuncName.substr(pos + 2);

            // NOTE: The analyzed function type might not be available here.
            auto vFuncOffset = vFuncIdx * addrSize;
            vftBuilder.AddMemberAtOffset(
                Type::PointerType(addrSize, vFunc->GetType(), true), vFuncName, vFuncOffset);
            vFuncIdx++;
        }
        m_view->DefineType(typeId, vftTypeName,
                           Confidence(TypeBuilder::StructureType(vftBuilder.Finalize()).Finalize(), RTTI_CONFIDENCE));
    }

    auto vftName = fmt::format("_vtable_for_{}", classInfo.className);
    // TODO: How to display base classes?
    if (classInfo.baseClassName.has_value())
        vftName += fmt::format("{{for `{}'}}", classInfo.baseClassName.value());
    auto vftSymbol = m_view->GetSymbolByAddress(vftAddr);
    if (vftSymbol != nullptr)
        m_view->UndefineAutoSymbol(vftSymbol);
    m_view->DefineAutoSymbol(new Symbol{DataSymbol, vftName, vftAddr});
    m_view->DefineDataVariable(vftAddr, Confidence(Type::NamedType(m_view, vftTypeName), RTTI_CONFIDENCE));
    return vftInfo;
}


ItaniumRTTIProcessor::ItaniumRTTIProcessor(const Ref<BinaryView> &view, bool useMangled, bool checkRData, bool vftSweep)
{
    m_view = view;
    m_logger = new Logger("Itanium RTTI");
    allowMangledClassNames = useMangled;
    checkWritableRData = checkRData;
    m_classInfo = {};
    virtualFunctionTableSweep = vftSweep;

    auto metadata = view->QueryMetadata(VIEW_METADATA_RTTI);
    if (metadata != nullptr)
    {
        // Load in metadata to the processor.
        DeserializedMetadata(RTTIProcessorType::Itanium, metadata);
    }
}


void ItaniumRTTIProcessor::ProcessRTTI()
{
    auto start_time = std::chrono::high_resolution_clock::now();
    auto addrSize = m_view->GetAddressSize();
    // TODO: This probably needs to change
    uint64_t maxTypeInfoSize = 0x10;

    auto scan = [&](const Ref<Section> &section) {
        for (uint64_t currAddr = section->GetStart(); currAddr <= section->GetEnd() - maxTypeInfoSize; currAddr += addrSize)
        {
            if (auto classInfo = ProcessRTTI(currAddr))
                m_classInfo[currAddr] = classInfo.value();
        }
    };

    // Scan data sections for rtti.
    for (const Ref<Section> &section: m_view->GetSections())
    {
        if (section->GetSemantics() == ReadOnlyDataSectionSemantics)
        {
            m_logger->LogDebug("Attempting to find RTTI in section %llx", section->GetStart());
            scan(section);
        }
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_time = end_time - start_time;
    m_logger->LogInfo("ProcessRTTI took %f seconds", elapsed_time.count());
}


void ItaniumRTTIProcessor::ProcessVFT()
{
   std::map<uint64_t, uint64_t> vftMap = {};
    std::map<uint64_t, std::optional<VirtualFunctionTableInfo>> vftFinishedMap = {};
    auto start_time = std::chrono::high_resolution_clock::now();
    for (auto &[coLocatorAddr, classInfo]: m_classInfo)
    {
        for (auto &ref: m_view->GetDataReferences(coLocatorAddr))
        {
            // Skip refs from other type info.
            DataVariable dv;
            if (m_view->GetDataVariableAtAddress(ref, dv) && m_classInfo.find(dv.address) != m_classInfo.end())
                continue;
            // TODO: This is not pointing at where it should, remember that the vtable will be inside another structure.
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
            for (uint64_t vtableAddr = startAddr; vtableAddr < endAddr - 0x10; vtableAddr += addrSize)
            {
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

    auto GetCachedVFTInfo = [&](uint64_t vftAddr, ClassInfo& classInfo) {
        // Check in the cache so that we don't process vfts more than once.
        auto cachedVftInfo = vftFinishedMap.find(vftAddr);
        if (cachedVftInfo != vftFinishedMap.end())
            return cachedVftInfo->second;
        auto vftInfo = ProcessVFT(vftAddr, classInfo);
        vftFinishedMap[vftAddr] = vftInfo;
        return vftInfo;
    };

    for (const auto &[coLocatorAddr, vftAddr]: vftMap)
    {
        auto classInfo = m_classInfo.find(coLocatorAddr)->second;
        if (classInfo.baseClassName.has_value())
        {
            // Process base vtable and add it to the class info.
            for (auto [baseCoLocAddr, baseClassInfo] : m_classInfo)
            {
                if (baseClassInfo.className == classInfo.baseClassName.value())
                {
                    uint64_t baseVftAddr = vftMap[baseCoLocAddr];
                    if (auto baseVftInfo = GetCachedVFTInfo(baseVftAddr, baseClassInfo))
                    {
                        classInfo.baseVft = baseVftInfo.value();
                        break;
                    }
                }
            }
        }

        if (auto vftInfo = GetCachedVFTInfo(vftAddr, classInfo))
            classInfo.vft = vftInfo.value();

        m_classInfo[coLocatorAddr] = classInfo;
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_time = end_time - start_time;
    m_logger->LogInfo("ProcessVFT took %f seconds", elapsed_time.count());
}