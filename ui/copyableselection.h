#pragma once
#include "qabstractitemmodel.h"
#include "uitypes.h"

constexpr int CopySelectionRole = Qt::UserRole + 100;

class BINARYNINJAUIAPI CopyableSelection
{
public:
    virtual ~CopyableSelection() = default;

    virtual QModelIndexList selectionList() = 0;
    virtual void copySelection();
    virtual bool canCopySelection();
};