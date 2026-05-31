//
// Created by kat on 5/23/23.
//

#ifndef KERNELCACHE_KERNELCACHEVIEW_H
#define KERNELCACHE_KERNELCACHEVIEW_H

#include <binaryninjaapi.h>

class KernelCacheView : public BinaryNinja::BinaryView
{
	bool m_parseOnly;
	BinaryNinja::Ref<BinaryNinja::Logger> m_logger;

public:
	KernelCacheView(const std::string& typeName, BinaryView* data, bool parseOnly = false);

	~KernelCacheView() override = default;

	bool Init() override;

	// Initialized the shared cache controller for this view. This is what allows us to load images and regions.
	bool InitController();

	virtual bool PerformIsExecutable() const override { return true; }
};


class KernelCacheViewType : public BinaryNinja::BinaryViewType
{
public:
	KernelCacheViewType();

	static void Register();

	BinaryNinja::Ref<BinaryNinja::BinaryView> Create(BinaryNinja::BinaryView* data) override;

	BinaryNinja::Ref<BinaryNinja::BinaryView> Parse(BinaryNinja::BinaryView* data) override;

	bool IsTypeValidForData(BinaryNinja::BinaryView* data) override;

	bool IsDeprecated() override { return false; }

	bool HasNoInitialContent() override { return true; }

	BinaryNinja::Ref<BinaryNinja::Settings> GetLoadSettingsForData(BinaryNinja::BinaryView* data) override;
};


#endif  // KERNELCACHE_KERNELCACHEVIEW_H
