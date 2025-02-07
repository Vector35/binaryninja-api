//
// Created by kat on 5/23/23.
//

#ifndef SHAREDCACHE_DSCVIEW_H
#define SHAREDCACHE_DSCVIEW_H

#include <binaryninjaapi.h>


class DSCView : public BinaryNinja::BinaryView {
	bool m_parseOnly;
public:

    DSCView(const std::string &typeName, BinaryView *data, bool parseOnly = false);

	~DSCView() override;

    bool Init() override;
};


class DSCViewType : public BinaryNinja::BinaryViewType {

public:
    DSCViewType();

    BinaryNinja::Ref<BinaryNinja::BinaryView> Create(BinaryNinja::BinaryView *data) override;

    BinaryNinja::Ref<BinaryNinja::BinaryView> Parse(BinaryNinja::BinaryView *data) override;

    bool IsTypeValidForData(BinaryNinja::BinaryView *data) override;

    bool IsDeprecated() override { return false; }

    BinaryNinja::Ref<BinaryNinja::Settings> GetLoadSettingsForData(BinaryNinja::BinaryView *data) override;
};


#endif //SHAREDCACHE_DSCVIEW_H
