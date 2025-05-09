#include "rtti.h"

using namespace BinaryNinja;
using namespace BinaryNinja::RTTI;


std::optional<std::string> RTTI::DemangleNameMS(BinaryView* view, bool allowMangled, const std::string &mangledName)
{
    QualifiedName demangledName = {};
    Ref<Type> outType = {};
    if (!DemangleMS(view->GetDefaultArchitecture(), mangledName, outType, demangledName, true))
        return DemangleNameLLVM(allowMangled, mangledName);
    return demangledName.GetString();
}


std::optional<std::string> RTTI::DemangleNameGNU3(BinaryView* view, bool allowMangled, const std::string &mangledName)
{
    QualifiedName demangledName = {};
    Ref<Type> outType = {};

    std::string adjustedMangledName = mangledName;
    // For some reason some of the names that start with ZN are not prefixed by `_`.
    if (adjustedMangledName.rfind("ZN", 0) == 0)
        adjustedMangledName = "_" + adjustedMangledName;
    // GCC emits a leading * to indicate that the type info is internal and its
    // name can be compared via pointer equality. It is not part of the type name.
    if (adjustedMangledName.rfind("*", 0) == 0)
        adjustedMangledName = adjustedMangledName.substr(1);
    // All types at this point should have a _Z prefix, if not, we likely need to just call the demangler directly, as this
    // function is specific to dealing with mangled _type_ names.
    if (adjustedMangledName.rfind("_Z", 0) != 0)
        adjustedMangledName = "_Z" + adjustedMangledName;

    if (!DemangleGNU3(view->GetDefaultArchitecture(), adjustedMangledName, outType, demangledName, true))
        return allowMangled ? std::optional(mangledName) : std::nullopt;

    // Because we might have a generic name such as "PackageListGui::PackageListGui" returned, we must attempt to
    // stringify the returned type IF its function type and then append that to the end of the demangled name.
    // REAL: PackageListGui::PackageListGui(Filesystem::Path&&, PackageListGui::UnderSubheader, bool)::$_1[0x0]
    // MANGLED: ZN14PackageListGuiC1EON10Filesystem4PathENS_14UnderSubheaderEbE3$_1
    // GENERIC DEMANGLED: PackageListGui::PackageListGui
    // UPDATED DEMANGLED: PackageListGui::PackageListGui(Filesystem::Path&&, PackageListGui::UnderSubheader, bool)
    if (outType && outType->IsFunction())
        demangledName.push_back(outType->GetStringAfterName(view->GetDefaultPlatform()));

    return demangledName.GetString();
}


std::string RemoveItaniumPrefix(std::string &name)
{
    // Remove numerical prefixes.
    while (!name.empty() && std::isdigit(name[0]))
        name = name.substr(1);
    return name;
}


std::optional<std::string> RTTI::DemangleNameItanium(BinaryView* view, bool allowMangled, const std::string &mangledName)
{
    // NOTE: Passing false to allowMangled to fallthrough to GNU3 demangler.
    if (auto demangledName = DemangleNameLLVM(false, mangledName))
        return RemoveItaniumPrefix(demangledName.value());
    if (auto demangledName = DemangleNameGNU3(view, allowMangled, mangledName))
        return RemoveItaniumPrefix(demangledName.value());
    return std::nullopt;
}


std::optional<std::string> RTTI::DemangleNameLLVM(bool allowMangled, const std::string &mangledName)
{
    QualifiedName demangledName = {};
    Ref<Type> outType = {};
    if (!DemangleLLVM(mangledName, demangledName, true))
        return allowMangled ? std::optional(mangledName) : std::nullopt;
    auto demangledNameStr = demangledName.GetString();
    size_t beginFind = demangledNameStr.find_first_of(' ');
    if (beginFind != std::string::npos)
        demangledNameStr.erase(0, beginFind + 1);
    size_t endFind = demangledNameStr.find(" `RTTI Type Descriptor Name'");
    if (endFind != std::string::npos)
        demangledNameStr.erase(endFind, demangledNameStr.length());
    return demangledNameStr;
}


Ref<Metadata> BaseClassInfo::SerializedMetadata() const
{
    std::map<std::string, Ref<Metadata>> baseClassMeta;
    baseClassMeta["className"] = new Metadata(className);
    baseClassMeta["classOffset"] = new Metadata(offset);
    // NOTE: We omit base vft functions as it can be resolved manually and just bloats the size.
    if (vft.has_value())
        baseClassMeta["vft"] = vft->SerializedMetadata(false);
    return new Metadata(baseClassMeta);
}

BaseClassInfo BaseClassInfo::DeserializedMetadata(const Ref<Metadata> &metadata)
{
    std::map<std::string, Ref<Metadata>> baseClassMeta = metadata->GetKeyValueStore();
    std::string className = baseClassMeta["className"]->GetString();
    uint64_t offset = baseClassMeta["classOffset"]->GetUnsignedInteger();
    BaseClassInfo baseClassInfo = {className, offset};
    if (baseClassMeta.find("vft") != baseClassMeta.end())
        baseClassInfo.vft = VirtualFunctionTableInfo::DeserializedMetadata(baseClassMeta["vft"]);
    return baseClassInfo;
}


Ref<Metadata> ClassInfo::SerializedMetadata() const
{
    std::map<std::string, Ref<Metadata>> classInfoMeta;
    classInfoMeta["processor"] = new Metadata(static_cast<uint64_t>(processor));
    classInfoMeta["className"] = new Metadata(className);
    if (!baseClasses.empty())
    {
        std::vector<Ref<Metadata> > basesMeta;
        basesMeta.reserve(baseClasses.size());
        for (const auto& baseClass : baseClasses)
            basesMeta.emplace_back(baseClass.SerializedMetadata());
        classInfoMeta["bases"] = new Metadata(basesMeta);
    }
    if (vft.has_value())
        classInfoMeta["vft"] = vft->SerializedMetadata();
    return new Metadata(classInfoMeta);
}


ClassInfo ClassInfo::DeserializedMetadata(const Ref<Metadata> &metadata)
{
    std::map<std::string, Ref<Metadata>> classInfoMeta = metadata->GetKeyValueStore();
    std::string className = classInfoMeta["className"]->GetString();
    RTTIProcessorType processor = static_cast<RTTIProcessorType>(classInfoMeta["processor"]->GetUnsignedInteger());
    ClassInfo info = {processor, className};
    if (classInfoMeta.find("bases") != classInfoMeta.end())
    {
        for (auto &entry: classInfoMeta["bases"]->GetArray())
            info.baseClasses.emplace_back(BaseClassInfo::DeserializedMetadata(entry));
    }
    if (classInfoMeta.find("vft") != classInfoMeta.end())
        info.vft = VirtualFunctionTableInfo::DeserializedMetadata(classInfoMeta["vft"]);
    return info;
}


Ref<Metadata> VirtualFunctionTableInfo::SerializedMetadata(const bool serializeFunctions) const
{
    std::map<std::string, Ref<Metadata>> vftMeta;
    vftMeta["address"] = new Metadata(address);
    // NOTE: We allow omitting baseVft functions as it can be resolved manually and just bloats the size.
    if (serializeFunctions && !virtualFunctions.empty())
    {
        std::vector<Ref<Metadata> > funcsMeta;
        funcsMeta.reserve(virtualFunctions.size());
        for (auto &vFunc: virtualFunctions)
            funcsMeta.emplace_back(vFunc.SerializedMetadata());
        vftMeta["functions"] = new Metadata(funcsMeta);
    }
    return new Metadata(vftMeta);
}


VirtualFunctionTableInfo VirtualFunctionTableInfo::DeserializedMetadata(const Ref<Metadata> &metadata)
{
    std::map<std::string, Ref<Metadata>> vftMeta = metadata->GetKeyValueStore();
    VirtualFunctionTableInfo vftInfo = {vftMeta["address"]->GetUnsignedInteger()};
    if (vftMeta.find("functions") != vftMeta.end())
    {
        for (auto &entry: vftMeta["functions"]->GetArray())
            vftInfo.virtualFunctions.emplace_back(VirtualFunctionInfo::DeserializedMetadata(entry));
    }
    return vftInfo;
}


Ref<Metadata> VirtualFunctionInfo::SerializedMetadata() const
{
    std::map<std::string, Ref<Metadata>> vFuncMeta;
    vFuncMeta["address"] = new Metadata(funcAddr);
    return new Metadata(vFuncMeta);
}


VirtualFunctionInfo VirtualFunctionInfo::DeserializedMetadata(const Ref<Metadata> &metadata)
{
    std::map<std::string, Ref<Metadata>> vFuncMeta = metadata->GetKeyValueStore();
    VirtualFunctionInfo vFuncInfo = {vFuncMeta["address"]->GetUnsignedInteger()};
    return vFuncInfo;
}


Ref<Metadata> RTTIProcessor::SerializedMetadata()
{
    std::map<std::string, Ref<Metadata>> classesMeta;
    for (auto &[objectAddr, classInfo]: m_classInfo)
    {
        auto addrStr = std::to_string(objectAddr);
        classesMeta[addrStr] = classInfo.SerializedMetadata();
    }

    for (auto &[objectAddr, classInfo]: m_unhandledClassInfo)
    {
        auto addrStr = std::to_string(objectAddr);
        // Unhandled class info will be discarded if handled class info exists for the same address.
        if (classesMeta.find(addrStr) == classesMeta.end())
            classesMeta[addrStr] = classInfo.SerializedMetadata();
    }

    std::map<std::string, Ref<Metadata>> itaniumMeta;
    itaniumMeta["classes"] = new Metadata(classesMeta);
    return new Metadata(itaniumMeta);
}


void RTTIProcessor::DeserializedMetadata(RTTIProcessorType type, const Ref<Metadata> &metadata)
{
    std::map<std::string, Ref<Metadata>> msvcMeta = metadata->GetKeyValueStore();
    if (msvcMeta.find("classes") != msvcMeta.end())
    {
        for (auto &[objectAddrStr, classInfoMeta]: msvcMeta["classes"]->GetKeyValueStore())
        {
            uint64_t objectAddr = std::stoull(objectAddrStr);
            auto classInfo = ClassInfo::DeserializedMetadata(classInfoMeta);
            if (classInfo.processor == type)
                m_classInfo[objectAddr] = classInfo;
            else
                m_unhandledClassInfo[objectAddr] = classInfo;
        }
    }
}