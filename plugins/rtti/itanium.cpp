#include "itanium.h"

#include <chrono>

using namespace BinaryNinja;
using namespace BinaryNinja::RTTI;
using namespace BinaryNinja::RTTI::Itanium;

// TODO: Need to add the boiler plate stuff
// TODO: Can we find the object offset for the vtable entry?
// TODO: Itanium doesnt really say anything about the sizing of these fields, i assume they are all u32 for thje most part.

constexpr const char *TYPE_SOURCE_ITANIUM = "rtti_itanium";
constexpr int MAX_FAILED_SCAN_ATTEMPTS = 10;


// Some fields are not always u32, use this if it goes from u32 -> u16 on 32bit
uint64_t ArchFieldSize(BinaryView *view)
{
    return view->GetAddressSize() / 2;
}


uint64_t TypeInfoSize(BinaryView *view)
{
    return view->GetAddressSize() * 2;
}


// TODO: Delete this function when access semantics are not so screwy.
bool IsOffsetReadOnlyData(BinaryView *view, uint64_t offset)
{
    // Check to see if the section has default section semantics and let it pass.
    for (const auto& section : view->GetSectionsAt(offset))
    {
        // TODO: Adding external here is weird but its whatever. This whole function needs to go away anyways.
        switch (section->GetSemantics())
        {
            case DefaultSectionSemantics:
            case ReadOnlyDataSectionSemantics:
            case ExternalSectionSemantics:
                return true;
            default:
                return false;
        }
    }

    return false;
}


std::optional<TypeInfo> GetTypeInfo(BinaryView* view, uint64_t address)
{
    // TODO: We really need a valid offset range thing.
    const auto typeInfoSize = TypeInfoSize(view);
    if (!view->IsValidOffset(address) || !view->IsValidOffset(address + typeInfoSize))
        return std::nullopt;
    BinaryReader reader = BinaryReader(view);
    reader.Seek(address);
    auto base = reader.ReadPointer();
    if (!view->IsValidOffset(base) || view->IsOffsetCodeSemantics(base))
        return std::nullopt;
    auto typeNameAddr = reader.ReadPointer();
    // NOTE: This used to check IsOffsetCodeSemantics but for some reason the default section semantics
    // is picked up as code. This really makes me sad. Hopefully the offset semantics rework is done soon!
    if (!view->IsValidOffset(typeNameAddr) || !IsOffsetReadOnlyData(view, typeNameAddr))
        return std::nullopt;
    reader.Seek(typeNameAddr);
    auto type_name = reader.ReadCString(512);
    return TypeInfo(base, type_name);
}


TypeInfo::TypeInfo(BinaryView *view, uint64_t address)
{
    auto typeInfo = GetTypeInfo(view, address);
    // TODO: Throw an exception? No one should call this directly unless they are sure!
    if (!typeInfo.has_value())
        return;
    base = typeInfo->base;
    type_name = typeInfo->type_name;
}


SIClassTypeInfo::SIClassTypeInfo(BinaryView *view, uint64_t address) : ClassTypeInfo(view, address)
{
    BinaryReader reader = BinaryReader(view);
    // TODO: Manually seeking to the offset is ugly.
    reader.Seek(address + TypeInfoSize(view));
    base_type = reader.ReadPointer();
}


BaseClassTypeInfo::BaseClassTypeInfo(BinaryView *view, uint64_t address)
{
    BinaryReader reader = BinaryReader(view);
    reader.Seek(address);
    base_type = reader.ReadPointer();
    // I thought the spec was pretty clear about these being u32
    // but apparently not? Or atleast on the gcc compiler I have these get turned to u16, disappointing.
    if (view->GetAddressSize() == 8)
    {
        offset_flags = reader.Read32();
        offset_flags_masks = reader.Read32();
    }
    else
    {
        offset_flags = reader.Read16();
        offset_flags_masks = reader.Read16();
    }
}

uint64_t BaseClassTypeSize(BinaryView *view)
{
    return view->GetAddressSize() + 0x8;
 }

VMIClassTypeInfo::VMIClassTypeInfo(BinaryView *view, uint64_t address) : ClassTypeInfo(view, address)
{
    BinaryReader reader = BinaryReader(view);
    // TODO: Manually seeking to the offset is ugly.
    reader.Seek(address + TypeInfoSize(view));
    flags = reader.Read32();
    base_count = reader.Read32();
    base_info = {};
    for (size_t i = 0; i < base_count; i++)
    {
        uint64_t currentBaseAddr = reader.GetOffset();
        base_info.emplace_back(view, currentBaseAddr);
        reader.Seek(currentBaseAddr + BaseClassTypeSize(view));
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
        structureBuilder.SetWidth(TypeInfoSize(view));

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
        uint64_t baseOffset = TypeInfoSize(view);

        StructureBuilder structureBuilder;
        Ref<Type> pBaseType = Type::PointerType(arch, Type::VoidType());
        structureBuilder.AddMemberAtOffset(pBaseType, "__base_type", baseOffset);
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
        // u32 on 64 and u16 on 32, see comment in BaseClassTypeInfo::BaseClassTypeInfo
        uint64_t enumSize = ArchFieldSize(view);

        EnumerationBuilder enumerationBuilder;
        enumerationBuilder.AddMemberWithValue("__virtual_mask", 0x1);
        enumerationBuilder.AddMemberWithValue("__public_mask", 0x2);
        enumerationBuilder.AddMemberWithValue("__offset_shift", 0x8);

        Ref<Type> enumerationType = TypeBuilder::EnumerationType(arch, enumerationBuilder.Finalize(), enumSize).Finalize();
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
        // u32 on 64 and u16 on 32, see comment in BaseClassTypeInfo::BaseClassTypeInfo
        uint64_t fieldSize = ArchFieldSize(view);
        Ref<Type> uintType = Type::IntegerType(fieldSize, false);

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
    uint64_t baseOffset = TypeInfoSize(view);

    StructureBuilder structureBuilder;
    structureBuilder.AddMemberAtOffset(VMIFlagsMasksType(view), "__flags", baseOffset);
    structureBuilder.AddMemberAtOffset(uintType, "__base_count", baseOffset + 0x4);
    Ref<Type> baseInfoType = Type::ArrayType(BaseClassTypeInfoType(view), baseCount);
    structureBuilder.AddMemberAtOffset(baseInfoType, "__base_info", baseOffset + 0x8);
    BaseStructure classTypeInfoBase = BaseStructure(ClassTypeInfoType(view), 0);
    structureBuilder.SetBaseStructures({classTypeInfoBase});

    return TypeBuilder::StructureType(structureBuilder.Finalize()).Finalize();
}

static Ref<Symbol> DetectPotentialCopyRelocatedVTable(BinaryView* view, uint64_t address)
{
    // 32-bit ELF binaries that are dynamically linked to the C++ runtime may use a
    // copy relocation for the vtable. The vtable itself will be defined in the .bss
    // section, and the copy relocation will cause the dynamic linker to populate it
    // at load time from the C++ runtime library.
    //
    // Detect this by looking for a symbol pointing to the start of the vtable data,
    // two pointers before the vtable address.

    int64_t vtableSymbolOffset = -(view->GetAddressSize() * 2);
    if (!view->IsValidOffset(address) || !view->IsValidOffset(address + vtableSymbolOffset))
        return nullptr;

    // ELFView does not add a relocation record for RELOC_COPY so we use hueristics here.
    if (view->IsOffsetBackedByFile(address))
        return nullptr;
    if (!view->IsOffsetWritableSemantics(address))
        return nullptr;

    auto sym = view->GetSymbolByAddress(address + vtableSymbolOffset);
    if (!sym || sym->GetShortName().find("__cxxabiv1") == std::string::npos)
        return nullptr;

    return sym;
}

std::optional<TypeInfoVariant> ReadTypeInfoVariant(BinaryView *view, uint64_t objectAddr)
{
    auto typeInfo = GetTypeInfo(view, objectAddr);
    if (!typeInfo.has_value())
        return std::nullopt;

    // If there is a symbol at objectAddr pointing to a symbol starting with "vtable for __cxxabiv1"
    Ref<Symbol> baseSym = GetRealSymbol(view, objectAddr, typeInfo->base);

    if (!baseSym)
        baseSym = DetectPotentialCopyRelocatedVTable(view, typeInfo->base);

    if (baseSym == nullptr)
    {
        // Verify first that we can even read a pointer sized value at the base.
        if (!view->IsValidOffset(typeInfo->base - view->GetAddressSize()))
            return std::nullopt;
        // We did not find a symbol for the base.
        // Last resort, try and deref to check for static linked c++ rt.
        // to get the c++ variant assume we are in a vtable like this
        // void* data_102bb4ca0 = _typeinfo_for___cxxabiv1::__class_type_info
        // void *data_102bb4ca8 = __cxxabiv1::__class_type_info::~__class_type_info() <--- typeInfo.base points to this.
        // void *data_102bb4cb0 = __cxxabiv1::__class_type_info::~__class_type_info()
        // While we could just deref to get the symbol of the vfunc, the symbol might not actually be present for that function yet.
        // So instead we will deref to the type info above the supposed vtable.
        // TODO: We should really just deref into the type info to get the name string.
        BinaryReader reader = BinaryReader(view);
        reader.Seek(typeInfo->base - view->GetAddressSize());
        // Read the type info pointer above the vft
        uint64_t typeInfoAddr = reader.ReadPointer();
        if (!view->IsValidOffset(typeInfoAddr))
            return std::nullopt;
        auto typeInfoSym = view->GetSymbolByAddress(typeInfoAddr);
        if (typeInfoSym == nullptr)
        {
            // For stripped binaries there will be no symbol, contruct a type info object and check.
            auto rootTypeInfo = GetTypeInfo(view, typeInfoAddr);
            if (!rootTypeInfo.has_value())
                return std::nullopt;
            if (rootTypeInfo->type_name.find("__cxxabiv1") == std::string::npos)
                return std::nullopt;
            typeInfoSym = new Symbol(DataSymbol, fmt::format("_typeinfo_for_{}", rootTypeInfo->type_name), typeInfoAddr);
        }
        baseSym = typeInfoSym;
    }

    auto baseSymName = baseSym->GetShortName();
    if (baseSymName.find("__cxxabiv1") != std::string::npos)
    {
        // Skip char array base data variables. This fixes the root base types being constructed twice at 0x0 and +0x8.
        // 1400f81a0  void* _typeinfo_for___cxxabiv1::__class_type_info = data_1400fce10 <---- First at 0x0
        // 1400f81a8  struct __cxxabiv1::__class_type_info _typeinfo_for_��@ = <----- Second at 0x8
        DataVariable baseDV;
        if (view->GetDataVariableAtAddress(typeInfo->base, baseDV) && baseDV.type->IsArray())
            return std::nullopt;

        // symbol takes the form of `abi::base_name::addend`
        if (baseSymName.find("si_class_type_info") != std::string::npos)
            return TIVSIClass;
        if (baseSymName.find("vmi_class_type_info") != std::string::npos)
            return TIVVMIClass;
        if (baseSymName.find("class_type_info") != std::string::npos)
            return TIVClass;
    }

    return std::nullopt;
}


std::optional<BaseClassInfo> ItaniumRTTIProcessor::ProcessVFTBaseClassInfo(uint64_t vftAddr, ClassInfo &classInfo)
{
    BinaryReader reader = BinaryReader(m_view);
    // Because we have this we _need_ to have the adjustment stuff.
    // NOTE: We assume two field sized ints with the first being what we want.
    // Two 0x4 ints and the pointer to the type info.
    reader.Seek(vftAddr - ((ArchFieldSize(m_view) * 2) + m_view->GetAddressSize()));

    auto adjustmentOffset = static_cast<int32_t>(reader.Read32());
    [[maybe_unused]]
    auto baseIdx = static_cast<int32_t>(reader.Read32());
    uint64_t classOffset = std::abs(adjustmentOffset);

    std::optional<BaseClassInfo> selectedBaseClassInfo = std::nullopt;
    // Assuming we do not have a baseClassInfo already passed we can deduce it here.
    for (auto& baseClass : classInfo.baseClasses)
    {
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
    if (!className.has_value() || className->empty())
        return std::nullopt;
    auto classInfo = ClassInfo{RTTIProcessorType::Itanium, className.value()};

    auto nameFromTypeInfoSymbol = [&](uint64_t addr) -> std::optional<std::string> {
        auto sym = m_view->GetSymbolByAddress(addr);
        if (sym == nullptr || sym->GetType() != ExternalSymbol)
            return std::nullopt;
        auto symName = sym->GetShortName();
        // Remove type info prefix.
        if (symName.rfind("_typeinfo_for_", 0) == 0)
            return symName.substr(14);
        if (symName.rfind("typeinfo_for_", 0) == 0)
            return symName.substr(13);
        return std::nullopt;
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
            m_logger->LogDebugF("Non-backed external subtype for {:#x}", objectAddr);
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
            m_logger->LogWarnF("Skipping base class with mangled name {:#x}", siClassTypeInfo.base_type);
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
                m_logger->LogDebugF("Non-backed external subtype for {:#x}", objectAddr);
                subTypeName = externTypeName.value();
            }
            else
            {
                auto baseTypeInfo = TypeInfo(m_view, baseInfo.base_type);
                subTypeName = baseTypeInfo.type_name;
            }
            auto baseClassName = DemangleNameItanium(m_view, allowMangledClassNames, subTypeName);
            if (!baseClassName.has_value())
            {
                m_logger->LogWarnF("Skipping base class with mangled name {:#x}", baseInfo.base_type);
                continue;
            }
            // Shift off the flag bits.
            uint64_t offset = baseInfo.offset_flags >> 8;
            auto baseClassInfo = BaseClassInfo {baseClassName.value(), offset};
            classInfo.baseClasses.emplace_back(baseClassInfo);
        }
        m_view->DefineDataVariable(objectAddr, Confidence(VMIClassTypeInfoType(m_view, vmiClassTypeInfo.base_count), 255));
    }
    else
    {
        m_view->DefineDataVariable(objectAddr, Confidence(ClassTypeInfoType(m_view), 255));
    }

    // Defining the data variable was a success, so we can add the symbol now.
    auto typeInfoName = fmt::format("_typeinfo_for_{}", classInfo.className);
    auto typeInfoSymbol = m_view->GetSymbolByAddress(objectAddr);
    if (typeInfoSymbol != nullptr)
        m_view->UndefineAutoSymbol(typeInfoSymbol);
    m_view->DefineAutoSymbol(new Symbol{DataSymbol, typeInfoName, objectAddr});

    return classInfo;
}


std::optional<VirtualFunctionTableInfo> ItaniumRTTIProcessor::ProcessVFT(uint64_t vftAddr, ClassInfo &classInfo, std::optional<BaseClassInfo> baseClassInfo)
{
    VirtualFunctionTableInfo vftInfo = {vftAddr};
    // Gather all virtual functions
    std::vector<VirtualFunctionInfo> virtualFunctions = {};
    uint64_t currentVftEntry = vftAddr;
    while (true)
    {
        uint64_t vFuncAddr = 0;
        const FunctionDiscoverState state = DiscoverVirtualFunction(currentVftEntry, vFuncAddr);
        if (state == FunctionDiscoverState::Failed)
            break;
        currentVftEntry += m_view->GetAddressSize();
        virtualFunctions.emplace_back(VirtualFunctionInfo{vFuncAddr});
    }

    if (virtualFunctions.empty())
    {
        m_logger->LogDebugF("Skipping empty virtual function table... {:#x}", vftAddr);
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
                LogWarnF("Skipping adjustments for base VFT with more functions than sub VFT... {:#x}", vftAddr);
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
                    m_logger->LogWarnF("Skipping vfunc with no type... {:#x}", vFunc.funcAddr);
                    return std::nullopt;
                }
                vFuncType = dv.type.GetValue();

                vFuncSym = m_view->GetSymbolByAddress(vFunc.funcAddr);
                if (vFuncSym == nullptr)
                {
                    m_logger->LogWarnF("Skipping vfunc with no symbol... {:#x}", vFunc.funcAddr);
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
		m_view->DefineType(typeId, vftTypeName, TypeBuilder::StructureType(vftBuilder.Finalize()).Finalize());
	}

	auto vftName = fmt::format("_vtable_for_{}", classInfo.className);
	// TODO: How to display base classes?
	if (baseClassInfo.has_value())
		vftName += fmt::format("{{for `{}'}}", baseClassInfo->className);
	auto vftSymbol = m_view->GetSymbolByAddress(vftAddr);
	if (vftSymbol != nullptr)
		m_view->UndefineAutoSymbol(vftSymbol);
	m_view->DefineAutoSymbol(new Symbol {DataSymbol, vftName, vftAddr});
	m_view->DefineDataVariable(vftAddr, Confidence(Type::NamedType(m_view, vftTypeName), RTTI_CONFIDENCE));
	return vftInfo;
}


ItaniumRTTIProcessor::ItaniumRTTIProcessor(const Ref<BinaryView> &view, bool useMangled, bool checkRData, bool vftSweep)
{
    m_view = view;
    m_logger = view->CreateLogger("Itanium RTTI");
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
    Ref<BackgroundTask> bgTask = new BackgroundTask("Scanning for Itanium RTTI...", true);
    auto start_time = std::chrono::high_resolution_clock::now();
    auto addrSize = m_view->GetAddressSize();
    uint64_t maxTypeInfoSize = TypeInfoSize(m_view);

    auto scan = [&](const Ref<Section> &section) {
        int failedAttempts = 0;
        for (uint64_t currAddr = section->GetStart(); currAddr <= section->GetEnd() - maxTypeInfoSize; currAddr += addrSize)
        {
            if (bgTask->IsCancelled())
                break;
            try
            {
                if (auto classInfo = ProcessRTTI(currAddr))
                    m_classInfo[currAddr] = classInfo.value();
            }
            catch (std::exception& e)
            {
                if (failedAttempts++; failedAttempts > MAX_FAILED_SCAN_ATTEMPTS)
                    break;
                m_logger->LogWarnForExceptionF(e, "Failed to process object at {:#x}... skipping", currAddr);
            }
        }

        if (failedAttempts > MAX_FAILED_SCAN_ATTEMPTS)
            m_logger->LogWarnF("Too many failed scans for section {:#x}... skipping", section->GetStart());
    };

    BulkSymbolModification bulkSymbolModification(m_view);
    // Scan data sections for rtti.
    for (const Ref<Section> &section : m_view->GetSections())
    {
        if (bgTask->IsCancelled())
            break;
        auto sectionSemantics = section->GetSemantics();
        // Some RTTI unfortunately will get put into a DefaultSectionSemantics section, so we have to check those.
        if (sectionSemantics == ReadOnlyDataSectionSemantics || sectionSemantics == DefaultSectionSemantics)
        {
            // If a malformed binary makes the binary view set up unbacked sections we should not attempt to read in them.
            if (m_view->ReadBuffer(section->GetStart(), 4).GetLength() == 4)
            {
                m_logger->LogDebugF("Attempting to find RTTI in section {:#x}", section->GetStart());
                scan(section);
            }
            else
            {
                m_logger->LogDebugF("Unbacked start for section {:#x}... skipping", section->GetStart());
            }
        }
    }
    bulkSymbolModification.End();

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

    bgTask->Finish();
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_time = end_time - start_time;
    m_logger->LogDebugF("ProcessRTTI took {} seconds", elapsed_time.count());
}


void ItaniumRTTIProcessor::ProcessVFT()
{
    Ref<BackgroundTask> bgTask = new BackgroundTask("Scanning for Itanium VFTs...", true);
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
            // Verify that there is two field sized values above the type info pointer
            optReader.Seek(ref - ArchFieldSize(m_view) * 2);
            if (!m_view->IsValidOffset(optReader.GetOffset()))
                continue;
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

    size_t processedNum = 0;
    for (const auto &[coLocatorAddr, vftAddrs]: vftMap)
    {
        if (bgTask->IsCancelled())
            break;
        for (const auto& vftAddr: vftAddrs)
            populateVftEntries(coLocatorAddr, vftAddr);
        std::string progress = fmt::format("Processing Itanium VFTs... {}/{}", processedNum++, vftMap.size());
        bgTask->SetProgressText(progress);
    }

    bgTask->Finish();
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_time = end_time - start_time;
    m_logger->LogDebugF("ProcessVFT took {} seconds", elapsed_time.count());
}
