#pragma once

#include <QtCore/QThread>
#include <QtCore/QStringListModel>
#include <QtWidgets/QDialog>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QComboBox>
#include "binaryninjaapi.h"
#include "uicontext.h"

/*!

    \defgroup createstructdialog CreateStructDialog
    \ingroup uiapi
*/

/*!

    \ingroup createstructdialog
*/
class BINARYNINJAUIAPI GetStructuresListThread : public QThread
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
	GetStructuresListThread(BinaryViewRef view, const std::function<void()>& completeFunc);
	void cancel();

	const QStringList& getTypes() const { return m_allTypes; }
};

/*!

    \ingroup createstructdialog
*/
class BINARYNINJAUIAPI BaseStructuresTableWidget : public QTableWidget
{
	Q_OBJECT

public:
	BaseStructuresTableWidget();
	virtual QSize sizeHint() const override;

protected:
	virtual void contextMenuEvent(QContextMenuEvent* event) override;

Q_SIGNALS:
	void removeBaseStructure(int idx);

private Q_SLOTS:
	void remove();
};

/*!

    \ingroup createstructdialog
*/
class BINARYNINJAUIAPI CreateStructDialog : public QDialog
{
	Q_OBJECT

	QLineEdit* m_name;
	QLineEdit* m_size;
	BaseStructuresTableWidget* m_baseTable;
	QComboBox* m_combo;
	QLineEdit* m_baseOffset;
	QPushButton* m_addBase;
	QCheckBox* m_propagateDataVarRefs;
	QCheckBox* m_pointer;

	BinaryViewRef m_view;
	BinaryNinja::QualifiedName m_resultName;
	uint64_t m_resultSize;
	bool m_resultDataVarRefs;
	bool m_resultPointer;
	bool m_askForPointer;
	QStringList m_historyEntries;
	int m_historySize;
	GetStructuresListThread* m_updateThread;
	QStringListModel* m_model;

	std::vector<BinaryNinja::BaseStructure> m_bases;

	virtual void customEvent(QEvent* event) override;

public:
	CreateStructDialog(QWidget* parent, BinaryViewRef view, const std::string& name, bool askForPointer = false,
		  bool defaultToPointer = false);

	BinaryNinja::QualifiedName getName() const { return m_resultName; }
	uint64_t getSize() const { return m_resultSize; }
	bool getPropagateDataVarRefs() const { return m_resultDataVarRefs; }
	bool getCreatePointer() const { return m_resultPointer; }
	const std::vector<BinaryNinja::BaseStructure> getBaseStructures() const { return m_bases; }

private Q_SLOTS:
	void createStruct();
	void addBase();
	void removeBaseStructure(int idx);

protected:
	virtual void showEvent(QShowEvent* e) override;
};
