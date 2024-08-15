#pragma once

#include <fstream>
#include <thread>

#include "GuidRenderer.h"
#include "ModuleType.h"
#include "TypePropagation.h"
#include "binaryninjaapi.h"
#include "highlevelilinstruction.h"
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"

using namespace BinaryNinja;
using namespace std;

typedef array<uint8_t, 16> EFI_GUID;

class Resolver {
protected:
    Ref<BinaryView> m_view;
    Ref<BackgroundTask> m_task;
    size_t m_width;
    map<EFI_GUID, pair<string, string>> m_protocol;
    map<EFI_GUID, string> m_user_guids;

    vector<pair<uint64_t, string>> m_service_usages;
    vector<pair<uint64_t, string>> m_protocol_usages;
    vector<pair<uint64_t, EFI_GUID>> m_guid_usages;
    vector<pair<uint64_t, string>> m_variable_usages;

    bool parseUserGuidIfExists(const string& filePath);
    bool parseProtocolMapping(const string& filePath);

    /*!
    For backward compatibility, if a user saved a bndb with older version Binary Ninja
    this function will try to retrieve types from Platform Types if it doesn't find one
    in BinaryView
    */
    Ref<Type> GetTypeFromViewAndPlatform(string type_name);
    void initProtocolMapping();

public:
    bool setModuleEntry(EFIModuleType fileType);
    bool resolveGuidInterface(Ref<Function> func, uint64_t addr, int guid_pos, int interface_pos);
    Resolver(Ref<BinaryView> view, Ref<BackgroundTask> task);

    pair<string, string> lookupGuid(EFI_GUID guidBytes);
    pair<string, string> defineAndLookupGuid(uint64_t addr);

    string nonConflictingName(const string& basename);
    static string nonConflictingLocalName(Ref<Function> func, const string& basename);

    /*!
    Define the structure used at the callsite with type `typeName`, propagate it to the data section. If it's a structure type, define it fields
    according to the `followFields` parameter. The input `addr` should be a call instruction
    \param func the function that contains the callsite (it's parent function)
    \param addr address of the callsite
    \param typeName the type that need to define
    \param paramIdx the parameter index that want to define
    \param followFields whether to define the structure's fields if they are pointers
    \return False if failed

    \b Example:
    \code{.cpp}
    refs = bv->GetCodeReferencesForType(QualifiedName("EFI_GET_VARIABLE"));
    for (auto ref : refs)
    {
        // ... some checking, need to make sure is a call instruction
        bool ok = defineTypeAtCallsite(ref.func, ref.addr, "EFI_GUID", 2, false);
    }
    \endcode
    */
    bool defineTypeAtCallsite(Ref<Function> func, uint64_t addr, string typeName, int paramIdx, bool followFields = false);
    vector<HighLevelILInstruction> HighLevelILExprsAt(Ref<Function> func, Ref<Architecture> arch, uint64_t addr);
};