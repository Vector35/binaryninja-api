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


std::string RemoveItaniumPrefix(const std::string& name) {
    // Remove class prefixes.
    // 1 and 7 is class_type
    // 9 is si_class_type
    // 1..4 is vmi_class_type
    if (name.rfind('1', 0) == 0)
        return name.substr(1);
    if (name.rfind('7', 0) == 0)
        return name.substr(1);
    if (name.rfind('9', 0) == 0)
        return name.substr(1);
    if (name.rfind("4", 0) == 0)
        return name.substr(2);
    return name;
}


std::optional<std::string> RTTI::DemangleNameItanium(BinaryView* view, bool allowMangled, const std::string &mangledName)
{
    if (auto demangledName = DemangleNameLLVM(allowMangled, mangledName))
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


Ref<Metadata> ClassInfo::SerializedMetadata()
{
    std::map<std::string, Ref<Metadata> > classInfoMeta;
    classInfoMeta["processor"] = new Metadata(static_cast<uint64_t>(processor));
    classInfoMeta["className"] = new Metadata(className);
    if (baseClassName.has_value())
        classInfoMeta["baseClassName"] = new Metadata(baseClassName.value());
    if (classOffset.has_value())
        classInfoMeta["classOffset"] = new Metadata(classOffset.value());
    if (vft.has_value())
        classInfoMeta["vft"] = vft->SerializedMetadata();
    // NOTE: We omit baseVft as it can be resolved manually and just bloats the size.
    return new Metadata(classInfoMeta);
}


ClassInfo ClassInfo::DeserializedMetadata(const Ref<Metadata> &metadata)
{
    std::map<std::string, Ref<Metadata> > classInfoMeta = metadata->GetKeyValueStore();
    std::string className = classInfoMeta["className"]->GetString();
    RTTIProcessorType processor = static_cast<RTTIProcessorType>(classInfoMeta["processor"]->GetUnsignedInteger());
    ClassInfo info = {processor, className};
    if (classInfoMeta.find("baseClassName") != classInfoMeta.end())
        info.baseClassName = classInfoMeta["baseClassName"]->GetString();
    if (classInfoMeta.find("classOffset") != classInfoMeta.end())
        info.classOffset = classInfoMeta["classOffset"]->GetUnsignedInteger();
    if (classInfoMeta.find("vft") != classInfoMeta.end())
        info.vft = VirtualFunctionTableInfo::DeserializedMetadata(classInfoMeta["vft"]);
    return info;
}


Ref<Metadata> VirtualFunctionTableInfo::SerializedMetadata()
{
    std::vector<Ref<Metadata> > funcsMeta;
    funcsMeta.reserve(virtualFunctions.size());
    for (auto &vFunc: virtualFunctions)
        funcsMeta.emplace_back(vFunc.SerializedMetadata());
    std::map<std::string, Ref<Metadata> > vftMeta;
    vftMeta["address"] = new Metadata(address);
    vftMeta["functions"] = new Metadata(funcsMeta);
    return new Metadata(vftMeta);
}


VirtualFunctionTableInfo VirtualFunctionTableInfo::DeserializedMetadata(const Ref<Metadata> &metadata)
{
    std::map<std::string, Ref<Metadata> > vftMeta = metadata->GetKeyValueStore();
    VirtualFunctionTableInfo vftInfo = {vftMeta["address"]->GetUnsignedInteger()};
    if (vftMeta.find("functions") != vftMeta.end())
    {
        for (auto &entry: vftMeta["functions"]->GetArray())
            vftInfo.virtualFunctions.emplace_back(VirtualFunctionInfo::DeserializedMetadata(entry));
    }
    return vftInfo;
}


Ref<Metadata> VirtualFunctionInfo::SerializedMetadata()
{
    std::map<std::string, Ref<Metadata> > vFuncMeta;
    vFuncMeta["address"] = new Metadata(funcAddr);
    return new Metadata(vFuncMeta);
}


VirtualFunctionInfo VirtualFunctionInfo::DeserializedMetadata(const Ref<Metadata> &metadata)
{
    std::map<std::string, Ref<Metadata> > vFuncMeta = metadata->GetKeyValueStore();
    VirtualFunctionInfo vFuncInfo = {vFuncMeta["address"]->GetUnsignedInteger()};
    return vFuncInfo;
}


Ref<Metadata> RTTIProcessor::SerializedMetadata()
{
    std::map<std::string, Ref<Metadata> > classesMeta;
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

    std::map<std::string, Ref<Metadata> > itaniumMeta;
    itaniumMeta["classes"] = new Metadata(classesMeta);
    return new Metadata(itaniumMeta);
}


void RTTIProcessor::DeserializedMetadata(RTTIProcessorType type, const Ref<Metadata> &metadata)
{
    std::map<std::string, Ref<Metadata> > msvcMeta = metadata->GetKeyValueStore();
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