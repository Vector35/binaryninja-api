#include "MessageHandler.h"

using namespace BinaryNinja;

MessageHandler::MessageHandler(Ref<BinaryView> data)
{
    m_msgSendFunctions = findMsgSendFunctions(data);
}

std::set<uint64_t> MessageHandler::findMsgSendFunctions(BinaryNinja::Ref<BinaryNinja::BinaryView> data)
{
    std::set<uint64_t> results;

    const auto authStubsSection = data->GetSectionByName("__auth_stubs");
    const auto stubsSection = data->GetSectionByName("__stubs");
    const auto authGotSection = data->GetSectionByName("__auth_got");
    const auto gotSection = data->GetSectionByName("__got");
    const auto laSymbolPtrSection = data->GetSectionByName("__la_symbol_ptr");

    // Shorthand to check if a symbol lies in a given section.
    auto sectionContains = [](Ref<Section> section, Ref<Symbol> symbol) {
        const auto start = section->GetStart();
        const auto length = section->GetLength();
        const auto address = symbol->GetAddress();

        return (uint64_t)(address - start) <= length;
    };

    // There can be multiple `_objc_msgSend` symbols in the same binary; there
    // may even be lots. Some of them are valid, others aren't. In order of
    // preference, `_objc_msgSend` symbols in the following sections are
    // preferred:
    //
    //   1. __auth_stubs
    //   2. __stubs
    //   3. __auth_got
    //   4. __got
    //   ?. __la_symbol_ptr
    //
    // There is often an `_objc_msgSend` symbol that is a stub function, found
    // in the `__stubs` section, which will come with an imported symbol of the
    // same name in the `__got` section. Not all `__objc_msgSend` calls will be
    // routed through the stub function, making it important to make note of
    // both symbols' addresses. Furthermore, on ARM64, the `__auth{stubs,got}`
    // sections are preferred over their unauthenticated counterparts.
    const auto candidates = data->GetSymbolsByName("_objc_msgSend");
    for (const auto& c : candidates) {
        if ((authStubsSection && sectionContains(authStubsSection, c))
            || (stubsSection && sectionContains(stubsSection, c))
            || (authGotSection && sectionContains(authGotSection, c))
            || (gotSection && sectionContains(gotSection, c))
            || (laSymbolPtrSection && sectionContains(laSymbolPtrSection, c))) {
            results.insert(c->GetAddress());
        }
    }

    return results;
}

bool MessageHandler::isMessageSend(uint64_t functionAddress)
{
    return m_msgSendFunctions.count(functionAddress);
}
