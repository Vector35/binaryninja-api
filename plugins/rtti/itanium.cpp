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
    if (!view->IsValidOffset(typeNameAddr))
        return;
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
    offset_flags_masks = reader.Read32();
}


VMIClassTypeInfo::VMIClassTypeInfo(BinaryView *view, uint64_t address) : ClassTypeInfo(view, address)
{
    BinaryReader reader = BinaryReader(view);
    // TODO: Manually seeking to the offset is ugly.
    reader.Seek(address + 0x10);
    flags = reader.Read32();
    base_count = reader.Read32();
    base_info = {};
    for (size_t i = 0; i < base_count; i++)
    {
        uint64_t currentBaseAddr = reader.GetOffset();
        base_info.emplace_back(view, currentBaseAddr);
        reader.Seek(currentBaseAddr + 0x10);
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


Ref<Type> VMIFlagsMasksType(BinaryView *view)
{
    auto typeId = Type::GenerateAutoTypeId(TYPE_SOURCE_ITANIUM, QualifiedName("VMIFlagsMasks"));
    Ref<Type> typeCache = view->GetTypeById(typeId);

    if (typeCache == nullptr)
    {
        Ref<Architecture> arch = view->GetDefaultArchitecture();
        Ref<Type> uintType = Type::IntegerType(4, false);

        EnumerationBuilder enumerationBuilder;
        enumerationBuilder.AddMemberWithValue("__non_diamond_repeat_mask", 0x1);
        enumerationBuilder.AddMemberWithValue("__diamond_shaped_mask", 0x2);

        Ref<Type> enumerationType = TypeBuilder::EnumerationType(arch, enumerationBuilder.Finalize()).Finalize();
        view->DefineType(typeId, QualifiedName("__cxxabiv1::__flags_masks"), enumerationType);

        typeCache = view->GetTypeById(typeId);
    }

    return typeCache;
}


Ref<Type> VMIClassTypeInfoType(BinaryView *view, uint64_t baseCount)
{
    Ref<Architecture> arch = view->GetDefaultArchitecture();
    Ref<Type> uintType = Type::IntegerType(4, false);

    StructureBuilder structureBuilder;
    structureBuilder.AddMemberAtOffset(VMIFlagsMasksType(view), "__flags", 0x10);
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


std::optional<BaseClassInfo> ItaniumRTTIProcessor::ProcessVFTBaseClassInfo(uint64_t vftAddr, ClassInfo &classInfo)
{
    BinaryReader reader = BinaryReader(m_view);
    // Because we have this we _need_ to have the adjustment stuff.
    // NOTE: We assume two 0x4 ints with the first being what we want.
    reader.Seek(vftAddr - 0x10);

    auto adjustmentOffset = static_cast<int32_t>(reader.Read32());
    auto baseIdx = static_cast<int32_t>(reader.Read32());
    uint64_t classOffset = std::abs(adjustmentOffset);

    std::optional<BaseClassInfo> selectedBaseClassInfo = std::nullopt;
    // Assuming we do not have a baseClassInfo already passed we can deduce it here.
    for (auto& baseClass : classInfo.baseClasses)
    {
        // if (baseClass.offset == 0)
        // {
        //     // If the base class is at offset 0 that means it has yet to be adjusted.
        //     // NOTE: This should only happen for `TIVSIClass`. If this assigns more than
        //     // one base class to this offset we are screwed.
        //     baseClass.offset = classOffset;
        //     LogInfo("Adjusting base class offset for %llx to %llx", vftAddr, classOffset);
        // }

        if (baseClass.offset == classOffset)
        {
            // Found the appropriate base class for this vtable.
            selectedBaseClassInfo = baseClass;
        }
    }

    // Return the selected base class for use in later processing such as `ProcessVFT`.
    return selectedBaseClassInfo;
}


std::optional<ClassInfo> ItaniumRTTIProcessor::ProcessRTTI(uint64_t objectAddr)
{
    // TODO: You cant get sub-object offsets from rtti, its stored above this ptr in vtable.
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

    auto nameFromTypeInfoSymbol = [&](uint64_t addr) -> std::optional<std::string> {
        auto sym = m_view->GetSymbolByAddress(addr);
        if (sym == nullptr || sym->GetType() != ExternalSymbol)
            return std::nullopt;
        auto symName = sym->GetShortName();
        // Remove type info prefix.
        if (symName.rfind("_typeinfo_for_", 0) != 0)
            return std::nullopt;
        return symName.substr(14);
    };

    if (typeInfoVariant == TIVSIClass)
    {
        // Read the base class.
        auto siClassTypeInfo = SIClassTypeInfo(m_view, objectAddr);
        auto subTypeInfoVariant = ReadTypeInfoVariant(m_view, siClassTypeInfo.base_type);
        std::string subTypeName;
        if (!subTypeInfoVariant.has_value())
        {
            // Allow externals to be used in place of a backed subtype.
            // TODO: We should probably warn that vtables will likely be inaccurate.
            // TODO: Because we wont know what offsets are valid.
            auto externTypeName = nameFromTypeInfoSymbol(siClassTypeInfo.base_type);
            if (!externTypeName.has_value())
                return std::nullopt;
            m_logger->LogDebug("Non-backed external subtype for %llx", objectAddr);
            subTypeName = externTypeName.value();
        }
        else
        {
            auto subTypeInfo = TypeInfo(m_view, siClassTypeInfo.base_type);
            subTypeName = subTypeInfo.type_name;
        }
        // Demangle base class name and set
        auto baseClassName = DemangleNameItanium(m_view, allowMangledClassNames, subTypeName);
        if (!baseClassName.has_value())
        {
            m_logger->LogWarn("Skipping base class with mangled name %llx", siClassTypeInfo.base_type);
            return std::nullopt;
        }
        // NOTE: The base class offset is not able to be resolved here.
        // NOTE: To resolve the base class offset you must go to the vtable.
        uint64_t baseClassOffset = 0;
        auto subBaseClassInfo = BaseClassInfo {baseClassName.value(), baseClassOffset};
        classInfo.baseClasses.emplace_back(subBaseClassInfo);
        m_view->DefineDataVariable(objectAddr, Confidence(SIClassTypeInfoType(m_view), 255));
    }
    else if (typeInfoVariant == TIVVMIClass)
    {
        auto vmiClassTypeInfo = VMIClassTypeInfo(m_view, objectAddr);
        m_view->DefineDataVariable(objectAddr, Confidence(VMIClassTypeInfoType(m_view, vmiClassTypeInfo.base_count), 255));
        for (const auto& baseInfo : vmiClassTypeInfo.base_info)
        {
            // Remove the flags and just get the offset
            auto baseTypeInfoVariant = ReadTypeInfoVariant(m_view, baseInfo.base_type);
            std::string subTypeName;
            if (!baseTypeInfoVariant.has_value())
            {
                // Allow externals to be used in place of a backed base type.
                auto externTypeName = nameFromTypeInfoSymbol(baseInfo.base_type);
                if (!externTypeName.has_value())
                    return std::nullopt;
                m_logger->LogDebug("Non-backed external subtype for %llx", objectAddr);
                subTypeName = externTypeName.value();
            } else
            {
                auto baseTypeInfo = TypeInfo(m_view, baseInfo.base_type);
                subTypeName = baseTypeInfo.type_name;
            }
            auto baseClassName = DemangleNameItanium(m_view, allowMangledClassNames, subTypeName);
            if (!baseClassName.has_value())
            {
                m_logger->LogWarn("Skipping base class with mangled name %llx", baseInfo.base_type);
                continue;
            }
            // Shift off the flag bits.
            uint64_t offset = baseInfo.offset_flags >> 8;
            auto baseClassInfo = BaseClassInfo {baseClassName.value(), offset};
            classInfo.baseClasses.emplace_back(baseClassInfo);
        }
    }
    else
    {
        m_view->DefineDataVariable(objectAddr, Confidence(ClassTypeInfoType(m_view), 255));
    }

    return classInfo;
}


std::optional<VirtualFunctionTableInfo> ItaniumRTTIProcessor::ProcessVFT(uint64_t vftAddr, ClassInfo &classInfo, std::optional<BaseClassInfo> baseClassInfo)
{
    VirtualFunctionTableInfo vftInfo = {vftAddr};
    BinaryReader reader = BinaryReader(m_view);
    reader.Seek(vftAddr);
    // Gather all virtual functions
    std::vector<VirtualFunctionInfo> virtualFunctions = {};
    while (true)
    {
        uint64_t vFuncAddr = reader.ReadPointer();
        auto funcs = m_view->GetAnalysisFunctionsForAddress(vFuncAddr);
        if (funcs.empty())
        {
            Ref<Segment> segment = m_view->GetSegmentAt(vFuncAddr);
            if (segment == nullptr || !(segment->GetFlags() & (SegmentExecutable | SegmentDenyWrite)))
            {
                // TODO: Sometimes vFunc idx will be zeroed iirc.
                // We allow vfuncs to point to extern functions.
                auto vFuncSym = m_view->GetSymbolByAddress(vFuncAddr);
                if (!vFuncSym)
                    break;
                DataVariable dv;
                bool foundDv = m_view->GetDataVariableAtAddress(vFuncAddr, dv);
                // Last virtual function, or hit the next vtable.
                if (!foundDv || !dv.type->m_object)
                    break;
                // Void externs are very likely to be a func.
                // TODO: Add some sanity checks for this!
                if (!dv.type->IsFunction() && !(dv.type->IsVoid() && vFuncSym->GetType() == ExternalSymbol))
                    break;
            }
            else
            {
                // TODO: Is likely a function check here?
                m_logger->LogDebug("Discovered function from virtual function table... %llx", vFuncAddr);
                m_view->AddFunctionForAnalysis(m_view->GetDefaultPlatform(), vFuncAddr, true);
            }
        }
        // Only ever add one function.
        virtualFunctions.emplace_back(VirtualFunctionInfo{vFuncAddr});
    }

    if (virtualFunctions.empty())
    {
        m_logger->LogDebug("Skipping empty virtual function table... %llx", vftAddr);
        return std::nullopt;
    }

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

        // TODO: Until https://github.com/Vector35/binaryninja-api/issues/5982 is fixed
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
                // TODO: Different type name please lol
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

        for (auto &&vFunc: virtualFunctions)
        {
            // NOTE: The analyzed function type might not be available here.
            auto vFuncAnalysis = m_view->GetAnalysisFunctionsForAddress(vFunc.funcAddr);
            Ref<Type> vFuncType = nullptr;
            Ref<Symbol> vFuncSym = nullptr;
            if (!vFuncAnalysis.empty())
            {
                vFuncType = vFuncAnalysis[0]->GetType();
                vFuncSym = vFuncAnalysis[0]->GetSymbol();
            } else
            {
                DataVariable dv;
                bool foundDv = m_view->GetDataVariableAtAddress(vFunc.funcAddr, dv);
                if (!foundDv)
                {
                    m_logger->LogWarn("Skipping vfunc with no type... %llx", vFunc.funcAddr);
                    return std::nullopt;
                }
                vFuncType = dv.type.GetValue();

                vFuncSym = m_view->GetSymbolByAddress(vFunc.funcAddr);
                if (vFuncSym == nullptr)
                {
                    m_logger->LogWarn("Skipping vfunc with no symbol... %llx", vFunc.funcAddr);
                    return std::nullopt;
                }
            }

            auto vFuncName = fmt::format("vFunc_{}", vFuncIdx);
            // If we have a better name, use it.
            auto vFuncSymName = vFuncSym->GetShortName();
            if (vFuncSymName.compare(0, 4, "sub_") != 0)
                vFuncName = vFuncSym->GetShortName();
            // MyClass::func -> func
            std::size_t pos = vFuncName.rfind("::");
            if (pos != std::string::npos)
                vFuncName = vFuncName.substr(pos + 2);

            auto vFuncOffset = vFuncIdx * addrSize;
            vftBuilder.AddMemberAtOffset(
                Type::PointerType(addrSize, vFuncType, true), vFuncName, vFuncOffset);
            vFuncIdx++;
        }
        m_view->DefineType(typeId, vftTypeName,
                           Confidence(TypeBuilder::StructureType(vftBuilder.Finalize()).Finalize(), RTTI_CONFIDENCE));
    }

    auto vftName = fmt::format("_vtable_for_{}", classInfo.className);
    // TODO: How to display base classes?
    if (baseClassInfo.has_value())
        vftName += fmt::format("{{for `{}'}}", baseClassInfo->className);
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

    m_view->BeginBulkModifySymbols();
    // Scan data sections for rtti.
    for (const Ref<Section> &section: m_view->GetSections())
    {
        if (section->GetSemantics() == ReadOnlyDataSectionSemantics)
        {
            m_logger->LogDebug("Attempting to find RTTI in section %llx", section->GetStart());
            scan(section);
        }
    }
    m_view->EndBulkModifySymbols();

    // Go through all classes and recurse into the base classes using the base class name
    for (auto &[classAddr, classInfo]: m_classInfo)
    {
        std::set<std::string> visitedBases;
        std::deque<BaseClassInfo> baseQueue(classInfo.baseClasses.begin(), classInfo.baseClasses.end());

        while (!baseQueue.empty())
        {
            BaseClassInfo baseClass = baseQueue.front();
            baseQueue.pop_front();

            if (visitedBases.find(baseClass.className) != visitedBases.end())
                continue;

            visitedBases.insert(baseClass.className);

            auto baseClassIt = std::find_if(m_classInfo.begin(), m_classInfo.end(),
                                            [&](const auto &item) {
                                                return item.second.className == baseClass.className;
                                            });

            if (baseClassIt != m_classInfo.end())
            {
                const ClassInfo &nestedBaseClassInfo = baseClassIt->second;
                baseQueue.insert(baseQueue.end(), nestedBaseClassInfo.baseClasses.begin(),
                                 nestedBaseClassInfo.baseClasses.end());
            }

            classInfo.baseClasses.push_back(baseClass);
        }

        // Remove duplicates in the baseClasses vector while preserving order
        std::sort(classInfo.baseClasses.begin(), classInfo.baseClasses.end(),
                  [](const BaseClassInfo &a, const BaseClassInfo &b) { return a.className < b.className; });

        classInfo.baseClasses.erase(
            std::unique(classInfo.baseClasses.begin(), classInfo.baseClasses.end(),
                        [](const BaseClassInfo &a, const BaseClassInfo &b) { return a.className == b.className; }),
            classInfo.baseClasses.end()
        );
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_time = end_time - start_time;
    m_logger->LogInfo("ProcessRTTI took %f seconds", elapsed_time.count());
}


void ItaniumRTTIProcessor::ProcessVFT()
{
    BinaryReader optReader = BinaryReader(m_view);
    std::map<uint64_t, std::set<uint64_t>> vftMap = {};
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
            // Verify that there is two 4 byte values above the type info pointer
            optReader.Seek(ref - 8);
            auto beforeTypeInfoRef = optReader.ReadPointer();
            if (m_view->IsValidOffset(beforeTypeInfoRef))
                continue;
            // TODO: This is not pointing at where it should, remember that the vtable will be inside another structure.
            auto vftAddr = ref + m_view->GetAddressSize();
            // Found a vtable reference to colocator
            // TODO: Access check here.
            vftMap[coLocatorAddr].insert(vftAddr);
        }
    }

    if (virtualFunctionTableSweep)
    {
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
                // vftMap[coLocatorAddr] = vtableAddr + addrSize;
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
        // We need to have base class info available here.
        // This works by reading off the adjustment and keying into the bases.
        // If there is a base at that adjustment we assume this vtable we are creating is for that.
        auto selectedBaseClass = ProcessVFTBaseClassInfo(vftAddr, classInfo);
        auto vftInfo = ProcessVFT(vftAddr, classInfo, selectedBaseClass);
        vftFinishedMap[vftAddr] = vftInfo;
        return vftInfo;
    };

    // Adds the VFT entries in class info and base class info.
    // TODO: This is so cursed.
    auto populateVftEntries = [&](uint64_t coLocatorAddr, uint64_t vftAddr) {
        auto classInfo = m_classInfo.find(coLocatorAddr)->second;
        for (auto& baseClassInfo : classInfo.baseClasses)
        {
            // Process base vtable and add it to the class info.
            for (auto& [baseCoLocAddr, bClassInfo] : m_classInfo)
            {
                if (bClassInfo.className == baseClassInfo.className)
                {
                    // Recurse into base class and populate all of its vtables.
                    for (auto& baseVftAddr : vftMap[baseCoLocAddr])
                    {
                        if (auto vftInfo = GetCachedVFTInfo(baseVftAddr, bClassInfo))
                            bClassInfo.vft = vftInfo.value();
                    }
                    // Now that we have populated all the vtables for the base class, we can assign its
                    // root vtable to the base vft.
                    baseClassInfo.vft = bClassInfo.vft;
                }
            }
        }

        if (auto vftInfo = GetCachedVFTInfo(vftAddr, classInfo))
            classInfo.vft = vftInfo.value();

        m_classInfo[coLocatorAddr] = classInfo;
    };

    for (const auto &[coLocatorAddr, vftAddrs]: vftMap)
    {
        for (const auto& vftAddr: vftAddrs)
        {
            populateVftEntries(coLocatorAddr, vftAddr);
        }
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_time = end_time - start_time;
    m_logger->LogInfo("ProcessVFT took %f seconds", elapsed_time.count());
}