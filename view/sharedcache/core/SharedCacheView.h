//
// Created by kat on 5/23/23.
//

#ifndef SHAREDCACHE_DSCVIEW_H
#define SHAREDCACHE_DSCVIEW_H

#include <binaryninjaapi.h>


class SharedCacheView : public BinaryNinja::BinaryView
{
	bool m_parseOnly;

public:
	SharedCacheView(const std::string& typeName, BinaryView* data, bool parseOnly = false);

	~SharedCacheView() override = default;

	bool Init() override;
};


class SharedCacheViewType : public BinaryNinja::BinaryViewType
{
public:
	SharedCacheViewType();

	static void Register();

	BinaryNinja::Ref<BinaryNinja::BinaryView> Create(BinaryNinja::BinaryView* data) override;

	BinaryNinja::Ref<BinaryNinja::BinaryView> Parse(BinaryNinja::BinaryView* data) override;

	bool IsTypeValidForData(BinaryNinja::BinaryView* data) override;

	bool IsDeprecated() override { return false; }

	BinaryNinja::Ref<BinaryNinja::Settings> GetLoadSettingsForData(BinaryNinja::BinaryView* data) override;
};


#endif  // SHAREDCACHE_DSCVIEW_H
