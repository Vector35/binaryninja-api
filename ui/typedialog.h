#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QLabel>
#include <QtCore/QStringListModel>
#include <QtWidgets/QComboBox>
#include <QtCore/QTimer>
#include <QtCore/QThread>
#include "binaryninjaapi.h"
#include "uitypes.h"


class BINARYNINJAUIAPI GetTypesListThread: public QThread
{
	Q_OBJECT

	QStringList m_allTypes;
	std::function<void()> m_completeFunc;
	std::mutex m_mutex;
	bool m_done;
	BinaryViewRef m_view;

protected:
	virtual void run() override;

public:
	GetTypesListThread(BinaryViewRef view, const std::function<void()>& completeFunc);
	void cancel();

	const QStringList& getTypes() const { return m_allTypes; }
};

class BINARYNINJAUIAPI TypeDialog: public QDialog
{
	Q_OBJECT

	QComboBox* m_combo;
	QStringListModel* m_model;
	QLabel* m_prompt;
	QString m_promptText;
	BinaryViewRef m_view;
	bool m_resultValid;
	QStringList m_historyEntries;
	int m_historySize;
	GetTypesListThread* m_updateThread;
	QFont m_defaultFont;
	bool m_initialTextSelection;
	BinaryNinja::QualifiedNameAndType m_type;
	QPushButton* m_acceptButton;
	QTimer* m_updateTimer;
	QPalette m_defaultPalette;
	QString m_parseError;

	void commitHistory();
	void customEvent(QEvent* event);

private Q_SLOTS:
	void accepted();
	void checkParse(QString text);
	void updateTimerEvent();

public:
	TypeDialog(QWidget* parent, BinaryViewRef view, const QString& title = "Specify Type",
		const QString& prompt = "Enter Type Name", const QString& existing="");
	~TypeDialog() { delete m_updateThread; }
	BinaryNinja::QualifiedNameAndType getType() const { return m_type; }
};