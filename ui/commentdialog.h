#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QTextEdit>
#include "binaryninjaapi.h"
#include "uicontext.h"
#include "uicomment.h"

/*!

	\defgroup commentdialog CommentDialog
 	\ingroup uiapi
*/

/*!

    \ingroup commentdialog
*/
class BINARYNINJAUIAPI CommentDialogTextEdit : public QTextEdit
{
	Q_OBJECT

public:
	CommentDialogTextEdit(QWidget* parent);

protected:
	virtual void keyPressEvent(QKeyEvent* event) override;

Q_SIGNALS:
	void contentAccepted();
};

/*!

    \ingroup commentdialog
*/
class BINARYNINJAUIAPI CommentDialog : public QDialog
{
	Q_OBJECT

	CommentDialogTextEdit* m_comment;
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