#pragma once

#include <binaryninjaapi.h>

class MessageHandler {

    std::set<uint64_t> m_msgSendFunctions;
    static std::set<uint64_t> findMsgSendFunctions(BinaryNinja::Ref<BinaryNinja::BinaryView> data);

public:
    MessageHandler(BinaryNinja::Ref<BinaryNinja::BinaryView> data);

    std::set<uint64_t> getMessageSendFunctions() const { return m_msgSendFunctions; }
    bool hasMessageSendFunctions() const { return m_msgSendFunctions.size() != 0; }
    bool isMessageSend(uint64_t);
};
