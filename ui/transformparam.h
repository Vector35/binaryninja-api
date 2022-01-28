#pragma once

#include <QtWidgets/QDialog>
#include "binaryninjaapi.h"
#include "uicontext.h"

class BINARYNINJAUIAPI TransformParameterDialog : public QDialog
{
	Q_OBJECT

	std::vector<BinaryNinja::TransformParameter> m_params;
	std::map<std::string, BinaryDataRef> m_paramData;

  public:
	TransformParameterDialog(
	    QWidget* parent, TransformRef xform, const std::vector<BinaryNinja::TransformParameter>& params);
	std::map<std::string, BinaryNinja::DataBuffer> getParameterData();
};
