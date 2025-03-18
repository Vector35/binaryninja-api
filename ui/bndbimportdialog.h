#pragma once

#include <QStandardItemModel>
#include <QSortFilterProxyModel>
#include <QtWidgets/QDialog>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QCheckBox>
#include <QtGui/QKeyEvent>
#include "binaryninjaapi.h"
#include "filter.h"
#include "uitypes.h"


constexpr int IndexRole = Qt::UserRole;
constexpr int ItemRole = Qt::UserRole + 1;
constexpr int LocationRole = Qt::UserRole + 2;
constexpr int IndexColumn = 0;
constexpr int NameColumn = 1;
constexpr int LocationColumn = 2;


class BndbImportFilterProxyModel : public QSortFilterProxyModel
{
	Q_OBJECT

protected:
	bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;

public:
	BndbImportFilterProxyModel(QObject* parent = nullptr) : QSortFilterProxyModel(parent) {}
	void updateFilter();
};


class BndbImportTreeView : public QTreeView
{
	Q_OBJECT
public:
	explicit BndbImportTreeView(QWidget *parent);

Q_SIGNALS:
	void addressDoubleClicked(uint64_t address);

protected:
	virtual void keyPressEvent(QKeyEvent* event) override;
};


/*!

	\ingroup uiapi
*/
class BINARYNINJAUIAPI BndbImportDialog : public QDialog, public FilterTarget
{
	Q_OBJECT

	FilteredView* m_filteredView;
	QWidget* m_filterWidget;
	QStandardItemModel* m_model;
	BndbImportFilterProxyModel* m_filterModel;
	QLineEdit* m_fileEdit;
	QPushButton* m_browseButton;
	QWidget* m_resultsWidget;
	BndbImportTreeView* m_typesTree;
	QPushButton* m_importButton;
	BinaryViewRef m_data;

	std::string m_filePath;

	struct SymbolAndType
	{
		SymbolAndType(SymbolRef name, TypeRef type): name(name), type(type) {}
		SymbolRef name;
		TypeRef type;
	};

	std::vector<BinaryNinja::QualifiedNameAndType> m_types;
	std::vector<SymbolAndType> m_functions;
	std::vector<SymbolAndType> m_functionsToImports;
	std::vector<SymbolAndType> m_dataVariables;

	enum ItemType {
		TypeItem,
		FunctionItem,
		FunctionToImportItem,
		DataVariableItem
	};

	BinaryViewRef m_incomingView;
	LoggerRef m_logger;

protected Q_SLOTS:
	void browseFile();
	void updateButtons();
	void previewTypes();
	void importTypes();

protected:
	virtual void keyPressEvent(QKeyEvent* event) override;

private:
	bool loadTypes();
	static bool isBuiltinType(const BinaryNinja::QualifiedName& name);
	static bool inSymbolBlackList(const SymbolRef sym);
	void applyFunctionTypes(const std::vector<SymbolAndType>& functions);
	void applyFunctionTypesToImports(const std::vector<SymbolAndType>& functions);
	void applyDataVariables(const std::vector<SymbolAndType>& dataVariables);
	std::vector<SymbolRef> matchingSymbol(const SymbolRef& sym, std::vector<BNSymbolType> allowed, bool allowPrefix);
	void navigateToItem(const QModelIndex& index);

public:
	BndbImportDialog(QWidget* parent, BinaryViewRef view);
	~BndbImportDialog() = default;

	void setFilter(const std::string& filter) override;
	void scrollToFirstItem() override;
	void scrollToCurrentItem() override;
	void selectFirstItem() override;
	void activateFirstItem() override;
	void closeFilter() override;
};
