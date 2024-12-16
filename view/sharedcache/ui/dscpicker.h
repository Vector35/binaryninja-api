//
// Created by kat on 5/22/23.
//

#ifndef SHAREDCACHE_DSCPICKER_H
#define SHAREDCACHE_DSCPICKER_H

#include <binaryninjaapi.h>
#include <ui/metadatachoicedialog.h>
void DisplayDSCPicker(UIContext* ctx = nullptr, BinaryNinja::Ref<BinaryNinja::BinaryView> dscView = nullptr);

#endif //SHAREDCACHE_DSCPICKER_H
