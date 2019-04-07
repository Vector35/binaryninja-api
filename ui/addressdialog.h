#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QLabel>
#include <QtCore/QStringListModel>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtCore/QTimer>
#include <QtCore/QThread>
#include "binaryninjaapi.h"
#include "uitypes.h"

class BINARYNINJAUIAPI GetSymbolsListThread: public QThread
{
	Q_OBJECT

	QStringList m_allSymbols;
	std::function<void()> m_completeFunc;
	std::mutex m_mutex;
	bool m_done;
	BinaryViewRef m_view;

protected:
	virtual void run() override;

public:
	GetSymbolsListThread(BinaryViewRef view, const std::function<void()>& completeFunc);
	void cancel();

	const QStringList& getSymbols() const { return m_allSymbols; }
};


class BINARYNINJAUIAPI AddressDialogWithPreview: public QDialog
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
	GetSymbolsListThread* m_updateThread;
    QColor m_defaultColor;
	QFont m_defaultFont;
	QString m_prompt;

	void commitHistory();
	void customEvent(QEvent* event);

private Q_SLOTS:
	void updateTimerEvent();
	void accepted();
	void updateRelativeState(int state);
	void updatePreview(QString text);

public:
	AddressDialogWithPreview(QWidget* parent, BinaryViewRef view, uint64_t here,
		const QString& title = "Go to Address", const QString& prompt = "Enter Expression");
	~AddressDialogWithPreview() { delete m_updateThread; }
	uint64_t getOffset() const { return m_addr; }
};
