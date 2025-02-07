#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QLabel>
#include <QtCore/QStringListModel>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtCore/QTimer>
#ifndef BINARYNINJAUI_BINDINGS
	#include <QtCore/QThread>
#endif
#include "binaryninjaapi.h"
#include "uitypes.h"
#include "getsymbolslistthread.h"

/*!

	\defgroup addressdialog AddressDialog
 	\ingroup uiapi
*/

/*!
    \ingroup addressdialog
*/
class BINARYNINJAUIAPI AddressDialogWithPreview : public QDialog
{
	Q_OBJECT

	QComboBox* m_combo;
	QStringListModel* m_model;
	QLabel* m_previewText;
	BinaryViewRef m_view;
	uint64_t m_addr;
	uint64_t m_here;
	QCheckBox* m_checkBox;
	bool m_resultValid;
	QTimer* m_updateTimer;
	QStringList m_historyEntries;
	int m_historySize;
	GetSymbolsListThread* m_updateThread = nullptr;
	QColor m_defaultColor;
	QFont m_defaultFont;
	QString m_prompt;
	bool m_initialTextSelection;
	std::string m_errorString;
	bool m_resultAmbiguous = false;

	void commitHistory();

private Q_SLOTS:
	void updateTimerEvent();
	void accepted();
	void updateRelativeState(Qt::CheckState state);
	void updatePreview();
	void updatePreviewText();
	void updatePreviewWithText(QString data);

public:
	AddressDialogWithPreview(QWidget* parent, BinaryViewRef view, uint64_t here, const QString& title = "Go to Address",
	    const QString& prompt = "Enter Expression", bool defaultToCurrent = false);
	~AddressDialogWithPreview();

	uint64_t getOffset() const { return m_addr; }
};

/*!
    \ingroup addressdialog
*/
class BINARYNINJAUIAPI FileOffsetDialogWithPreview : public QDialog
{
	Q_OBJECT

	QComboBox* m_combo;
	QLabel* m_previewText;
	BinaryViewRef m_view;
	uint64_t m_fileOffset;
	uint64_t m_here;
	bool m_resultValid;
	QTimer* m_updateTimer;
	QStringList m_historyEntries;
	int m_historySize;
	QColor m_defaultColor;
	QFont m_defaultFont;
	QString m_prompt;
	bool m_initialTextSelection;
	std::string m_errorString;
	bool m_resultAmbiguous = false;

	void commitHistory();

private Q_SLOTS:
	void updateTimerEvent();
	void accepted();
	void updatePreview();
	void updatePreviewText();
	void updatePreview(QString data);

public:
	FileOffsetDialogWithPreview(QWidget* parent, BinaryViewRef view, uint64_t here,
	    const QString& title = "Go to File Offset", const QString& prompt = "Enter Expression",
	    bool defaultToCurrent = false);
	~FileOffsetDialogWithPreview() {}

	uint64_t getOffset() const { return m_fileOffset; }
};

/*!
    \ingroup addressdialog
*/
class BINARYNINJAUIAPI AddUserXrefDialog : public QDialog
{
	Q_OBJECT

	QComboBox* m_combo;
	QStringListModel* m_model;
	QLabel *m_previewText, m_sizePrompt;
	QLineEdit* m_sizeInput;
	BinaryViewRef m_view;
	uint64_t m_addr;
	uint64_t m_here;
	size_t m_size;
	bool m_resultValid;
	QTimer* m_updateTimer;
	QStringList m_historyEntries;
	int m_historySize;
	GetSymbolsListThread* m_updateThread = nullptr;
	QColor m_defaultColor;
	QFont m_defaultFont;
	QString m_prompt;
	bool m_initialTextSelection;
	std::string m_errorString;
	bool m_resultAmbiguous = false;

	void commitHistory();

private Q_SLOTS:
	void updateTimerEvent();
	void accepted();
	void updatePreview();
	void updatePreviewText();
	void updatePreviewWithText(QString data);

public:
	AddUserXrefDialog(QWidget* parent, BinaryViewRef view, uint64_t here = 0, size_t size = 0,
	    const QString& title = "Add User Type Field Cross Reference",
	    const QString& sizeTitle = "Size of Reference (optional)", const QString& prompt = "Enter Expression",
	    bool defaultToCurrent = false);
	~AddUserXrefDialog();

	uint64_t getOffset() const { return m_addr; }
	size_t getSize() const { return m_size; }
};