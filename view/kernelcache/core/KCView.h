//
// Created by kat on 5/23/23.
//

#ifndef KERNELCACHE_KCVIEW_H
#define KERNELCACHE_KCVIEW_H

#include <binaryninjaapi.h>

class KCView : public BinaryNinja::BinaryView {
	bool m_parseOnly;
public:

    KCView(const std::string &typeName, BinaryView *data, bool parseOnly = false);

	~KCView() override;

    bool Init() override;

	virtual bool PerformIsExecutable() const override { return true; }
};


class KCViewType : public BinaryNinja::BinaryViewType {

public:
	KCViewType();

    BinaryNinja::Ref<BinaryNinja::BinaryView> Create(BinaryNinja::BinaryView *data) override;

    BinaryNinja::Ref<BinaryNinja::BinaryView> Parse(BinaryNinja::BinaryView *data) override;

    bool IsTypeValidForData(BinaryNinja::BinaryView *data) override;

    bool IsDeprecated() override { return false; }

    BinaryNinja::Ref<BinaryNinja::Settings> GetLoadSettingsForData(BinaryNinja::BinaryView *data) override;
};

#ifdef __cplusplus
extern "C" {
#endif
	void InitKCViewType();
#ifdef __cplusplus
};
#endif

#endif //KERNELCACHE_KCVIEW_H
