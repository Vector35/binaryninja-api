#pragma once

#include <QtCore/QSortFilterProxyModel>
#include <QtCore/QTimer>
#include <QtWidgets/QListView>
#include <QtWidgets/QStyledItemDelegate>
#include <QtWidgets/QWidget>

#include "binaryninjacore.h"
#include "dockhandler.h"
#include "filter.h"
#include "uitypes.h"
#include "viewframe.h"

/*!

	\defgroup variablelist VariableList
 	\ingroup uiapi
*/

/*! A variable list item can represent either a function-local variable, or a
	data variable referenced by the current function.

	\ingroup variablelist
*/
enum class VariableListItemType
{
	LocalVariable,
	DataVariable
};

/*! An item part of VariableListModel.

	\ingroup variablelist
*/
class VariableListItem
{
	FunctionRef m_func;
	VariableListItemType m_type;
	std::string m_name;

	uint64_t m_refPoint;

	BinaryNinja::Variable m_var;
	BinaryNinja::DataVariable m_dataVar;
	BinaryNinja::PossibleValueSet m_pvs;
	bool m_hasUidf;

  public:
	//! Create a new VariableListItem of the LocalVariable type.
	VariableListItem(
	    FunctionRef func, BinaryNinja::Variable var, BinaryNinja::PossibleValueSet pvs, bool hasUidf, std::string name);

	//! Create a new VariableListItem of the DataVariable type.
	VariableListItem(FunctionRef func, BinaryNinja::DataVariable dataVar, uint64_t refPoint, std::string name);

	//! Get the type of this list item.
	VariableListItemType type() const;

	//! Get the represented variable's display name.
	std::string name() const;

	//! Get the data variable's value; use with data variable items only.
	std::string constantValue() const;

	//! Get the variable possible value set; use with local variable items only.
	BinaryNinja::PossibleValueSet possibleValueSet() const;

	//! Is the PVS user-provided? Use with local variable items only.
	bool hasUidf() const;

	std::vector<BinaryNinja::InstructionTextToken> tokensBeforeName() const;
	std::vector<BinaryNinja::InstructionTextToken> tokensAfterName() const;

	//! Shorthand to get concatenated type, name, and value tokens.
	std::vector<BinaryNinja::InstructionTextToken> displayTokens() const;

	//! Get the represented variable; use with variable items only.
	BinaryNinja::Variable variable() const;

	//! Get the represented data variable; use with data variable items only.
	BinaryNinja::DataVariable dataVariable() const;

	//! Get the first use of this variable; use with data variables items only.
	uint64_t refPoint() const;

	//! Is any part of this item user-defined?
	bool isUserDefined() const;
};

Q_DECLARE_METATYPE(VariableListItem*);

/*! The backing model for the variable list widget, holds VariableListItem.

	\ingroup variablelist
*/
class BINARYNINJAUIAPI VariableListModel : public QAbstractListModel
{
	Q_OBJECT

	ViewFrame* m_view;
	BinaryViewRef m_data;
	FunctionRef m_func;
	BinaryNinja::FunctionViewType m_funcType;
	bool m_funcExceedsComplexity = false;
	BinaryNinja::AdvancedFunctionAnalysisDataRequestor m_analysisRequestor;
	std::vector<VariableListItem> m_items;

	std::set<BinaryNinja::ArchAndAddr> m_forcedFuncs;

	QItemSelectionModel* m_selModel;

	size_t m_prevVariableCount;
	uint64_t m_prevSelectionId;

  public:
	VariableListModel(QWidget* parent, ViewFrame* view, BinaryViewRef data);

	//! Clear the list's content.
	void clear();

	//! Get the current function.
	FunctionRef function() const;

	//! Get the current function type.
	const BinaryNinja::FunctionViewType& functionType() const;

	//! Whether or not the function exceeds the set complexity threshold
	bool functionExceedsComplexity() const { return m_funcExceedsComplexity; }

	//! Set the focused function and update the content of the list.
	void setFunction(FunctionRef func, const BinaryNinja::FunctionViewType& il, const HighlightTokenState& hts);

	//! Set the selection model, should correspond to the parent widget's.
	void setSelectionModel(QItemSelectionModel* model);

	virtual QVariant data(const QModelIndex& i, int role) const override;
	virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;
	virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	Qt::ItemFlags flags(const QModelIndex& index) const override;
	virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;

	void linkActivatedEvent(const QString& link);
};


class BINARYNINJAUIAPI VariableSortFilterProxyModel : public QSortFilterProxyModel
{

public:
	VariableSortFilterProxyModel(QObject* parent = nullptr) : QSortFilterProxyModel(parent) {}

	virtual bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;
};

/*!

	\ingroup variablelist
*/
class VariableListItemDelegate : public QStyledItemDelegate
{
	Q_OBJECT

  public:
	VariableListItemDelegate();

	void paint(QPainter* painter, const QStyleOptionViewItem& opt, const QModelIndex& index) const;
	QSize sizeHint(const QStyleOptionViewItem& opt, const QModelIndex& index) const;
};

/*! The main variable list dock widget.

	\ingroup variablelist
*/
class BINARYNINJAUIAPI VariableList : public SidebarWidget, public FilterTarget
{
	Q_OBJECT

	QWidget* m_header;
	FilterEdit* m_filterEdit;
	FilteredView* m_filteredList;

	ViewFrame* m_view;
	BinaryViewRef m_data;

	QSortFilterProxyModel* m_filteredListModel;
	VariableListModel* m_listModel;
	QListView* m_list;

	QWidget* m_complexityWarning;

	uint64_t m_lastOffset;
	QTimer* m_refreshTimer;

	void processRefresh();

	void variableDoubleClicked();

  public:
	VariableList(ViewFrame* view, BinaryViewRef data);

	QWidget* headerWidget() override { return m_header; }
	void focus() override { refresh(); }

	void refresh();

	//! Get the VariableListItem corresponding to the current selection.
	VariableListItem* selectedItem() const;

	//! Show the rename dialog for the selected variable.
	void changeSelectedVariableName();

	//! Show the new type dialog for the selected variable.
	void changeSelectedVariableType();

	//! Show the "merge variables" dialog for the selected variable.
	void mergeSelectedVariable();

	//! Clear the selected variable's name.
	void clearSelectedVariableName();

	//! Clear the selected variable's type.
	void clearSelectedVariableType();

	//! Undefine the selected variable's user symbol.
	void clearSelectedVariableNameAndType();

	//! Navigate to the first usage of the selected variable.
	void showSelectedVariableFirstUsage();

	//! Navigate to the definition of the selected data variable.
	void showSelectedDataVariableDefinition();

	//! Set the selected variable's DSE policy.
	void setSelectedVariableDeadStoreElimination(BNDeadStoreElimination dse);

	//! Prompt the user to set the selected variable's value
	void setSelectedVariableValue();

	//! Remove UIDF for the selected variable
	void resetSelectedVariableValue();

	virtual void setFilter(const std::string& filter) override;
	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void selectFirstItem() override;
	virtual void activateFirstItem() override;
};

/*! The main variable list dock widget.

	\ingroup variablelist
*/
class BINARYNINJAUIAPI VariableListSidebarWidgetType : public SidebarWidgetType
{
  public:
	VariableListSidebarWidgetType();
	virtual SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	virtual SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::RightContent; }
};
