#pragma once

#include <QDialog>
#include "binaryninjaapi.h"
#include "uitypes.h"

#ifdef DEMO_EDITION
class BINARYNINJAUIAPI FreeVersionLimitation: public QDialog
{
	Q_OBJECT

public:
	FreeVersionLimitation(const QString& feature = "");
};
#endif
