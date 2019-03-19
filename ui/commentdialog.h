#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QComboBox>
#include "binaryninjaapi.h"
#include "dialogtextedit.h"
#include "uicontext.h"

class BINARYNINJAUIAPI CommentDialog: public QDialog
{
	Q_OBJECT

	DialogTextEdit* m_comment;

public:
	CommentDialog(QWidget* parent, const QString& comment = "");
	QString getComment();
};
