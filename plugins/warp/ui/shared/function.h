#pragma once
#include <QStandardItemModel>
#include <QTableView>

#include "binaryninjaapi.h"
#include "constraint.h"
#include "filter.h"
#include "misc.h"
#include "warp.h"

class WarpFunctionItem : public QStandardItem
{
	Warp::Ref<Warp::Function> m_function;

	// Optional attached data used to show/manage the function.
	Warp::Ref<Warp::Container> m_container;
	std::optional<Warp::Source> m_source;

public:
	WarpFunctionItem(Warp::Ref<Warp::Function> function, BinaryNinja::Ref<BinaryNinja::Function> analysisFunction);

	void SetContainer(const Warp::Ref<Warp::Container>& container);

	void SetSource(Warp::Source source);

	Warp::Ref<Warp::Function> GetFunction() { return m_function; }
	Warp::Ref<Warp::Container> GetContainer() { return m_container; }
	std::optional<Warp::Source> GetSource() { return m_source; }
};

class WarpFunctionItemModel : public QStandardItemModel
{
	Q_OBJECT

	// The current matched function, used to highlight currently.
	Warp::Ref<Warp::Function> m_matchedFunction;

	// Mapping of function start address to the row index.
	// This is used to identify unique functions for updating instead of resetting the entire model.
	std::unordered_map<uint64_t, int> m_insertableFunctionRows;

public:
	WarpFunctionItemModel(const QStringList& labels, QObject* parent);

	static constexpr int COL_FUNCTION_ITEM = 0;
	static constexpr int COL_ADDRESS_ITEM = 1;

	void AppendFunction(WarpFunctionItem* item);

	void InsertFunction(uint64_t address, WarpFunctionItem* item);

	void RemoveFunction(uint64_t address);

	WarpFunctionItem* GetItem(const QModelIndex& index) const;

	std::optional<uint64_t> GetAddress(const QModelIndex& index) const;

	QVariant data(const QModelIndex& index, int role) const override;

	void SetMatchedFunction(const Warp::Ref<Warp::Function>& matchedFunction)
	{
		Warp::Ref<Warp::Function> previousMatchedFunction = m_matchedFunction;
		m_matchedFunction = matchedFunction;

		// Make sure to refresh the highlights so we don't keep the highlights from the previous function.
		if (previousMatchedFunction)
		{
			const QModelIndex topLeft = index(0, 0);
			const QModelIndex bottomRight = index(rowCount() - 1, 0);
			emit dataChanged(topLeft, bottomRight);
		}
	}

	Warp::Ref<Warp::Function> GetMatchedFunction() const { return m_matchedFunction; }
};

class WarpFunctionFilterModel : public QSortFilterProxyModel
{
	Q_OBJECT

public:
	WarpFunctionFilterModel(QObject* parent) : QSortFilterProxyModel(parent) {}

	~WarpFunctionFilterModel() override = default;

	bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;

	bool lessThan(const QModelIndex& sourceLeft, const QModelIndex& sourceRight) const override;
};

class WarpFunctionTableWidget : public QWidget, public FilterTarget
{
	Q_OBJECT

	QTableView* m_table;
	WarpFunctionItemModel* m_model;
	WarpFunctionFilterModel* m_proxyModel;
	FilterEdit* m_filterEdit;
	FilteredView* m_filterView;
	QMenu* m_contextMenu;
	std::map<QString, std::function<void(WarpFunctionItem*, std::optional<uint64_t>)>> m_contextMenuActions;
	std::map<QString, std::function<bool(WarpFunctionItem*, std::optional<uint64_t>)>> m_contextMenuIsValid;

public:
	explicit WarpFunctionTableWidget(QWidget* parent = nullptr);

	// TODO: Invert this and provide OnCallback functions that wrap the connect call.
	QTableView* GetTableView() const { return m_table; }
	WarpFunctionItemModel* GetModel() const { return m_model; }
	WarpFunctionFilterModel* GetProxyModel() const { return m_proxyModel; }

	void RegisterContextMenuAction(
		const QString& name, const std::function<void(WarpFunctionItem*, std::optional<uint64_t>)>& callback);

	void RegisterContextMenuAction(const QString& name,
		const std::function<void(WarpFunctionItem*, std::optional<uint64_t>)>& callback,
		const std::function<bool(WarpFunctionItem*, std::optional<uint64_t>)>& isValid);

	void SetFunctions(QVector<WarpFunctionItem*> functions);

	void InsertFunction(uint64_t address, WarpFunctionItem* function);

	void RemoveFunction(uint64_t address);

	void setFilter(const std::string&, FilterOptions options) override;

	void scrollToFirstItem() override {}

	void scrollToCurrentItem() override {}

	void ensureSelection() override {}

	void activateSelection() override {}
};

class WarpFunctionInfoWidget : public QWidget
{
	Q_OBJECT

	Warp::Ref<Warp::Function> m_function;
	BinaryNinja::Ref<BinaryNinja::Function> m_analysisFunction;

	// Optionally provide this information to show the source information.
	Warp::Ref<Warp::Container> m_container;
	std::string source;

	WarpConstraintTableWidget* m_constraintsTable;

	QTableView* m_commentsTable;
	QStandardItemModel* m_commentsModel;

	QTableView* m_variablesTable;

public:
	explicit WarpFunctionInfoWidget(QWidget* parent = nullptr);

	Warp::Ref<Warp::Function> GetFunction() { return m_function; }
	void SetFunction(Warp::Ref<Warp::Function> function) { m_function = function; };

	void SetAnalysisFunction(BinaryNinja::Ref<BinaryNinja::Function> analysisFunction)
	{
		m_analysisFunction = analysisFunction;
	};
	BinaryNinja::Ref<BinaryNinja::Function> GetAnalysisFunction() { return m_analysisFunction; }

	// TODO: Make this private?
	void UpdateInfo();
};
