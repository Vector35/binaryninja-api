#pragma once

#include <QtWidgets/QListView>
#include <QtCore/QAbstractItemModel>
#include <QtCore/QTimer>
#include <QtWidgets/QLineEdit>
#include <vector>
#include <set>
#include <mutex>
#include "binaryninjaapi.h"
#include "viewframe.h"
#include "filter.h"
#include "uicontext.h"
#include "menus.h"

#define FUNCTION_LIST_UPDATE_INTERVAL 250

class SymbolsView;
static std::string emptyArch;

class BINARYNINJAUIAPI SymbolListModel: public QAbstractItemModel, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT
public:
	enum SortType
	{
		SortAcendingAddresses,
		SortDecendingAddresses,
		SortAlphabeticallyAcending,
		SortAlphabeticallyDecending
	};

	struct NamedObject
	{
		SymbolRef sym;
		std::string archName;
		NamedObject() : sym(nullptr), archName(emptyArch) {}
		NamedObject(SymbolRef s, std::string& a=emptyArch) : sym(s), archName(a) {}
		NamedObject(const NamedObject& n)
		{
			sym = n.sym;
			archName = n.archName;
		}

		// NamedObject(const NamedObject&& n)
		// {
		// 	sym = std::move(n.sym);
		// 	archName = std::move(n.archName);
		// }

		// NamedObject& operation=(const NamedObject&& n)
		// {
		// 	sym = std::move(n.sym);
		// 	archName = std::move(n.archName);
		// }

		bool operator<(const NamedObject& other) const
		{
			if (getStart() < other.getStart())
				return true;
			if (getStart() == other.getStart() &&
				(sym->GetType() == FunctionSymbol && other.sym->GetType() == FunctionSymbol))
			{
				return archName < other.archName;
			}
			return false;
		}

		bool operator>(const NamedObject& other) const
		{
			if (getStart() > other.getStart())
				return true;
			if (getStart() == other.getStart() &&
				(sym->GetType() == FunctionSymbol && other.sym->GetType() == FunctionSymbol))
			{
				return archName > other.archName;
			}
			return false;
		}

		bool isFunc() const { return sym->GetType() == FunctionSymbol; }
		uint64_t getStart() const { return sym->GetAddress(); }
		std::string getName() const { return sym->GetFullName(); }
		BNSymbolType getType() const { return sym->GetType(); }
	};

private:
	enum SymbolListUpdateType
	{
		AddedToSymbolList,
		RemovedFromSymbolList,
		UpdatedInSymbolList
	};

	struct SymbolListUpdateEvent
	{
		NamedObject rec;
		SymbolListUpdateType type;
		SymbolListUpdateEvent(const NamedObject& r, SymbolListUpdateType t) : rec(r), type(t) {}
		SymbolListUpdateEvent(const SymbolListUpdateEvent& s)
		{
			rec = s.rec;
			type = s.type;
		}
	};

	class SymbolListUpdate: public BinaryNinja::RefCountObject
	{
		std::mutex m_mutex;
		bool m_valid;
		SymbolListModel* m_model;

	public:
		SymbolListUpdate(SymbolListModel* model);
		void start();
		void abort();
	};

	QWidget* m_funcList;
	ViewFrame* m_view;
	BinaryViewRef m_data;
	std::set<std::string> m_archNames;
	std::vector<NamedObject> m_allSyms;
	std::vector<NamedObject> m_curSyms;
	NamedObject m_currentSym;
	std::string m_filter;

	std::mutex m_updateMutex;
	std::vector<SymbolListUpdateEvent> m_updates;
	bool m_fullUpdate;

	BinaryNinja::Ref<SymbolListUpdate> m_backgroundUpdate;
	volatile bool m_backgroundUpdateComplete;
	std::vector<NamedObject> m_backgroundUpdateFuncs;

	bool m_showImports;
	bool m_showExports;
	bool m_showFunctions;
	bool m_showDataVars;
	SortType m_sortType;

	// static bool allSymbolComparison(const NamedObject& a, const NamedObject& b);
	static bool allSymbolComparisonLT(const NamedObject& a, const NamedObject& b);
	static bool allSymbolComparisonGE(const NamedObject& a, const NamedObject& b);
	static bool allSymbolComparisonNameLT(const NamedObject& a, const NamedObject& b);
	static bool allSymbolComparisonNameGE(const NamedObject& a, const NamedObject& b);
	typedef bool (*comparitor)(const NamedObject& a, const NamedObject& b);
	static comparitor getComparitor(SortType type)
	{
		switch (type)
		{
		case SortAcendingAddresses: return allSymbolComparisonLT;
		case SortDecendingAddresses: return allSymbolComparisonGE;
		case SortAlphabeticallyAcending: return allSymbolComparisonNameLT;
		case SortAlphabeticallyDecending:
		default:
			return allSymbolComparisonNameGE;
		}
	}
	void getValidObject(std::vector<NamedObject>& result);

public:
	SymbolListModel(QWidget* parent, ViewFrame* view, BinaryViewRef data);
	virtual ~SymbolListModel();

	virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
	virtual QModelIndex parent(const QModelIndex& i) const override;
	virtual bool hasChildren(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	virtual int columnCount(const QModelIndex& parent) const override;
	virtual QVariant data(const QModelIndex& i, int role) const override;

	virtual void OnAnalysisFunctionAdded(BinaryNinja::BinaryView* data, BinaryNinja::Function* func) override;
	virtual void OnAnalysisFunctionRemoved(BinaryNinja::BinaryView* data, BinaryNinja::Function* func) override;
	virtual void OnAnalysisFunctionUpdated(BinaryNinja::BinaryView* data, BinaryNinja::Function* func) override;
	virtual void OnDataVariableAdded(BinaryNinja::BinaryView* data, const BinaryNinja::DataVariable& var) override;
	virtual void OnDataVariableRemoved(BinaryNinja::BinaryView* data, const BinaryNinja::DataVariable& var) override;
	virtual void OnDataVariableUpdated(BinaryNinja::BinaryView* data, const BinaryNinja::DataVariable& var) override;

	void updateFonts();
	bool isValidType(const NamedObject& rec);
	bool setCurrentObject(const NamedObject& rec);
	bool setCurrentFunction(FunctionRef func);
	QModelIndex findSymbol(const NamedObject& rec);
	QModelIndex findCurrentSymbol();
	NamedObject getNamedObjectForIndex(int i);

	void updateFunctions();
	void backgroundUpdate();
	bool hasSymbols() const;

	void setFilter(const std::string& filter);
	void showExports(bool show) { m_showExports = show; }
	void showImports(bool show) { m_showImports = show; }
	void showFunctions(bool show) { m_showFunctions = show; }
	void showDataVars(bool show) { m_showDataVars = show; }

	void toggleExports() {
		m_showExports = !m_showExports;
		if (m_showExports)
		{
			m_showImports = false;
			m_showFunctions = true;
			m_showDataVars = true;
		}
	}
	void toggleImports() {
		m_showImports = !m_showImports;
		if (m_showImports && m_showExports)
			m_showExports = false;
	}
	void toggleFunctions() {
		m_showFunctions = !m_showFunctions;
		if (m_showFunctions && m_showExports)
			m_showExports = false;
	}
	void toggleDataVars() {
		m_showDataVars = !m_showDataVars;
		if (m_showDataVars && m_showExports)
			m_showExports = false;
	}

	bool getShowExports() const  { return m_showExports; }
	bool getShowImports() const  { return m_showImports; }
	bool getShowFunctions() const  { return m_showFunctions; }
	bool getShowDataVars() const  { return m_showDataVars; }

	void sortSymbols(SortType type);
	void setSortType(SortType type) { m_sortType = type; }
	SortType getSortType() const { return m_sortType; }
	NamedObject getCurrentSym() const { return m_currentSym; }

Q_SIGNALS:
	void afterListReset();
	void beforeListReset();
};


class BINARYNINJAUIAPI SymbolList: public QListView, public FilterTarget
{
	Q_OBJECT

	ViewFrame* m_view;
	BinaryViewRef m_data;
	SymbolsView* m_functionsView;
	SymbolListModel* m_list;
	QTimer* m_updateTimer;
	bool m_disableScrollToFunction;
	UIActionHandler m_actionHandler;
	Menu m_menu;
	ContextMenuManager m_contextMenuManager;

	bool m_showExports;
	bool m_showImports;
	bool m_showFunctions;
	bool m_showDataVars;
	std::string m_filter;
	SymbolListModel::SortType m_sortType;
	SymbolListModel::NamedObject m_index;
	int m_scrollPosition;
	bool m_doubleClick;

public:
	SymbolList(SymbolsView* parent, ViewFrame* frame, BinaryViewRef data);

	void updateFonts();
	void setCurrentFunction(FunctionRef func);

	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void selectFirstItem() override;
	virtual void activateFirstItem() override;
	virtual void setFilter(const std::string& filter) override;

	bool hasSymbols();

	virtual void copy();
	virtual void paste();
	virtual bool canCopy();
	void find();

	bool getShowExports() const { return m_list->getShowExports(); }
	bool getShowImports() const { return m_list->getShowImports(); }
	bool getShowFunctions() const { return m_list->getShowFunctions(); }
	bool getShowDataVars() const { return m_list->getShowDataVars(); }

	void toggleExports() { m_list->toggleExports(); }
	void toggleImports() { m_list->toggleImports(); }
	void toggleFunctions() { m_list->toggleFunctions(); }
	void toggleDataVars() { m_list->toggleDataVars(); }

protected:
	virtual void focusOutEvent(QFocusEvent* event) override;
	virtual void keyPressEvent(QKeyEvent* event) override;
	virtual void contextMenuEvent(QContextMenuEvent* /*event*/) override;

private Q_SLOTS:
	void goToSymbol(const QModelIndex& i);
	void updateTimerEvent();
	void savePosition();
	void restorePosition();
	void saveIndex(const QModelIndex& index);
	void clearIndex(const QModelIndex& index);
};
