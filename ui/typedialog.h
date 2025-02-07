#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QLabel>
#include <QtCore/QStringListModel>
#include <QtWidgets/QComboBox>
#include <QtCore/QTimer>
#ifndef BINARYNINJAUI_BINDINGS
	#include <QtCore/QThread>
#endif
#include "binaryninjaapi.h"
#include "uitypes.h"


#ifdef BINARYNINJAUI_BINDINGS
// QThread has issues working in the bindings on some platforms
class GetTypesListThread;
class ParseTypeThread;
#else

/*!

	\defgroup typedialog TypeDialog
 	\ingroup uiapi
*/

/*!

    \ingroup typedialog
*/
class BINARYNINJAUIAPI GetTypesListThread : public QThread
{
	Q_OBJECT

	QStringList m_allTypes;
	std::function<void()> m_completeFunc;
	std::mutex m_mutex;
	bool m_done;
	BinaryNinja::TypeContainer m_typeContainer;

  protected:
	virtual void run() override;

  public:
	GetTypesListThread(BinaryNinja::TypeContainer typeContainer, const std::function<void()>& completeFunc);
	void cancel();

	const QStringList& getTypes() const { return m_allTypes; }
};

Q_DECLARE_METATYPE(BinaryNinja::QualifiedNameAndType);

/*! QThread subclass for handling type string parsing to avoid UI interruptions.

    \ingroup typedialog
*/
class ParseTypeThread : public QThread
{
	Q_OBJECT

	std::optional<BinaryNinja::TypeContainer> m_typeContainer;
	std::string m_text;

	void run() override;

  Q_SIGNALS:
	void parsingComplete(bool valid, BinaryNinja::QualifiedNameAndType type, QString error);

  public:
	ParseTypeThread(std::optional<BinaryNinja::TypeContainer> typeContainer, QString text);
	void cancel();
};
#endif

/*!

    \ingroup typedialog
*/
class BINARYNINJAUIAPI TypeDialog : public QDialog
{
	Q_OBJECT

	QComboBox* m_combo;
	QStringListModel* m_model;
	QLabel* m_prompt;
	QString m_promptText;
	std::optional<BinaryNinja::TypeContainer> m_typeContainer;
	bool m_resultValid;
	QStringList m_historyEntries;
	int m_historySize;
	GetTypesListThread* m_updateThread;
	QFont m_defaultFont;
	bool m_initialTextSelection;
	BinaryNinja::QualifiedNameAndType m_type;
	QPushButton* m_acceptButton;
	QTimer* m_updateTimer;
	QTimer* m_parseTimer;
	bool m_isParsing;
	std::atomic_bool m_comboBoxTextChanged;
	QPalette m_defaultPalette;
	QString m_parseError;

	void commitHistory();
	void customEvent(QEvent* event);
	void saveLocation();
	void reject();
	void accept();
	void linkActivated(const QString& link);

  private Q_SLOTS:
	void accepted();
	void checkParse();
	void typeParsed(bool valid, BinaryNinja::QualifiedNameAndType type, QString error);
	void updateTimerEvent();

  public:
	TypeDialog(QWidget* parent, std::optional<BinaryNinja::TypeContainer> typeContainer, const QString& title = "Specify Type",
	    const QString& prompt = "Enter Type Name", const QString& existing = "");
	~TypeDialog();
	BinaryNinja::QualifiedNameAndType getType() const { return m_type; }
};
