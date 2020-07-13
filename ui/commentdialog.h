#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QComboBox>
#include "binaryninjaapi.h"
#include "dialogtextedit.h"
#include "uicontext.h"
#include "uicomment.h"

class BINARYNINJAUIAPI CommentDialog: public QDialog
{
	Q_OBJECT

	DialogTextEdit* m_comment;
	UIComment m_uicomment;

public:
	CommentDialog(QWidget* parent, const UIComment& comment);
	QString getNewComment();
	QString getCurrentComment();
	const FunctionRef& getCommentBackingFunction();
	const BinaryViewRef& getCommentBackingData();
	UICommentType getCommentType();
	uint64_t getCommentAddress();
};
