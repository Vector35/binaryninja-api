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
        return std::nullopt;
    if (baseSym->GetType() != ExternalSymbol)
        return std::nullopt;
    auto baseSymName = baseSym->GetShortName();

    // TODO: __vmi_class_type_info seems to point to operator delete(void*)
    // TODO: For now we just bruteforce it with the type_name check...

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
    else if (typeInfo.type_name.length() > 2)
    {
        // TODO: This is so ugly
        switch (typeInfo.type_name.at(0))
        {
            case '7':
                return TIVClass;
            case '9':
                return TIVSIClass;
            case '1':
                if (typeInfo.type_name.at(1) == '4')
                    return TIVVMIClass;
            default:
                return std::nullopt;
        }
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
    auto className = DemangleNameGNU3(m_view, allowMangledClassNames, typeInfo.type_name);
    if (!className.has_value())
        return std::nullopt;
    auto classInfo = ClassInfo{className.value()};

    // TODO: className starts with 7, 9, 14
    // 7 == class_type
    // 9 == si_class_type
    // 14 == vmi_class_type

    auto typeInfoName = fmt::format("_typeinfo_for_{}", classInfo.className);
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
        auto baseClassName = DemangleNameGNU3(m_view, allowMangledClassNames, subTypeInfo.type_name);
        if (!baseClassName.has_value())
        {
            m_logger->LogWarn("Skipping base class with mangled name %llx", siClassTypeInfo.base_type);
            return std::nullopt;
        }
        classInfo.baseClassName = baseClassName;
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


ItaniumRTTIProcessor::ItaniumRTTIProcessor(const Ref<BinaryView> &view, bool useMangled, bool checkRData, bool vftSweep) : m_view(view)
{
    m_logger = new Logger("Itanium RTTI");
    allowMangledClassNames = useMangled;
    checkWritableRData = checkRData;
    m_classInfo = {};
    virtualFunctionTableSweep = vftSweep;

    auto metadata = view->QueryMetadata(VIEW_METADATA_RTTI);
    if (metadata != nullptr)
    {
        // TODO: This will pull in microsoft RTTI, which is really weird behavior possibly.
        // Load in metadata to the processor.
        // DeserializedMetadata(metadata);
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