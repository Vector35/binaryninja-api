#pragma once

#include <QtWidgets/QListView>
#include <QtCore/QAbstractItemModel>
#include <QtCore/QTimer>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QStyledItemDelegate>
#include <vector>
#include <deque>
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

class BINARYNINJAUIAPI SymbolListDelegate: public QStyledItemDelegate
{
	Q_OBJECT
	QFont m_font;
	int m_height, m_charWidth;

public:
	SymbolListDelegate(QWidget* parent);
	void updateFonts();
	virtual QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override;
};

class BINARYNINJAUIAPI SymbolListModel: public QAbstractItemModel, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT
public:
	enum SortType
	{
		SortAscendingAddresses,
		SortDescendingAddresses,
		SortAlphabeticallyAscending,
		SortAlphabeticallyDescending
	};

	struct NamedObject
	{
		SymbolRef sym;
		std::string name;
		std::string rawName;
		NamedObject() : sym(nullptr) {}
		NamedObject(SymbolRef s) : sym(s)
		{
			name = sym->GetFullName();
			rawName = sym->GetRawName();
		}
		NamedObject(const NamedObject& n)
		{
			sym = n.sym;
			name = n.name;
			rawName = n.rawName;
		}

		NamedObject& operator=(const NamedObject& n)
		{
			sym = n.sym;
			name = n.name;
			rawName = n.rawName;
			return *this;
		}

		NamedObject(NamedObject&& n)
		{
			sym = std::move(n.sym);
			name = std::move(n.name);
			rawName = std::move(n.rawName);
		}

		NamedObject& operator=(NamedObject&& n)
		{
			sym = std::move(n.sym);
			name = std::move(n.name);
			rawName = std::move(n.rawName);
			return *this;
		}

		bool operator==(const NamedObject& other) const
		{
			return (getStart() == other.getStart()) && (getType() == other.getType());
		}

		bool operator!=(const NamedObject& other) const
		{
			return !((*this) == other);
		}

		bool operator<(const NamedObject& other) const
		{
			if (getStart() < other.getStart())
				return true;
			if ((*this) == other)
				return getType() < other.getType();
			return false;
		}

		bool operator>(const NamedObject& other) const
		{
			if (getStart() > other.getStart())
				return true;
			if ((*this) == other)
				return getType() > other.getType();
			return false;
		}

		bool isFunc() const { return (getType() == FunctionSymbol) || (getType() == ImportedFunctionSymbol) || (getType() == LibraryFunctionSymbol); }
		uint64_t getStart() const { return sym->GetAddress(); }
		std::string getName() const { return name; }
		std::string getRawName() const { return rawName; }

		bool lessThanAlpha(const NamedObject& other) const
		{
			if (name < other.name)
				return true;
			else if (name == other.name)
			{
				if (rawName < other.rawName)
					return true;
				if (rawName == other.rawName)
					return getStart() < other.getStart();
			}
			return false;
		}

		bool lessThanAlphaRaw(const NamedObject& other) const
		{
			if (rawName < other.rawName)
				return true;
			else if (rawName == other.rawName)
			{
				if (name < other.name)
					return true;
				if (name == other.name)
					return getStart() < other.getStart();
			}
			return false;
		}
		BNSymbolType getType() const { return sym->GetType(); }
	};

private:
	enum SymbolListUpdateType
	{
		UnnamedFunctionAddedToSymbolList,
		UnnamedDataAddedToSymbolList,
		SymbolAddedToSymbolList,
		SymbolUpdatedInSymbolList,
		SymbolRemovedFromSymbolList
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
	std::deque<NamedObject> m_allSyms;
	std::deque<NamedObject> m_curSyms;
	NamedObject m_currentSym;
	std::string m_filter;

	std::mutex m_updateMutex;
	std::vector<SymbolListUpdateEvent> m_updates;
	bool m_fullUpdate;

	BinaryNinja::Ref<SymbolListUpdate> m_backgroundUpdate;
	volatile bool m_backgroundUpdateComplete;
	std::deque<NamedObject> m_backgroundUpdateFuncs;

	bool m_showImports;
	bool m_showExportedDataVars;
	bool m_showExportedFunctions;
	bool m_showLocalFunctions;
	bool m_showLocalDataVars;
	SortType m_sortType;
	bool m_displayMangled;

	static bool symbolLessThan(const NamedObject& a, const NamedObject& b);
	static bool symbolNameLessThan(const NamedObject& a, const NamedObject& b);
	static bool symbolRawNameLessThan(const NamedObject& a, const NamedObject& b);

	void getValidObject(std::deque<NamedObject>& result);

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
	virtual void OnDataVariableAdded(BinaryNinja::BinaryView* data, const BinaryNinja::DataVariable& var) override;
	virtual void OnDataVariableRemoved(BinaryNinja::BinaryView* data, const BinaryNinja::DataVariable& var) override;

	virtual void OnSymbolAdded(BinaryNinja::BinaryView* data, BinaryNinja::Symbol* sym) override;
	virtual void OnSymbolUpdated(BinaryNinja::BinaryView* data, BinaryNinja::Symbol* sym) override;
	virtual void OnSymbolRemoved(BinaryNinja::BinaryView* data, BinaryNinja::Symbol* sym) override;

	void updateFonts();
	bool isValidType(const NamedObject& rec);
	bool setCurrentObject(const NamedObject& rec);
	bool setCurrentFunction(FunctionRef func);
	QModelIndex findSymbol(const NamedObject& rec) const;
	QModelIndex getSymbolIndex(const std::deque<NamedObject>::const_iterator rec) const;
	QModelIndex findCurrentSymbol() const;
	NamedObject getNamedObjectForIndex(int i) const;

	void updateFunctions();
	void backgroundUpdate();
	bool hasSymbols() const;

	void setFilter(const std::string& filter);
	void showExportedDataVars(bool show) { m_showExportedDataVars = show; }
	void showExportedFunctions(bool show) { m_showExportedFunctions = show; }
	void showLocalFunctions(bool show) { m_showLocalFunctions = show; }
	void showLocalDataVars(bool show) { m_showLocalDataVars = show; }
	void showImports(bool show) { m_showImports = show; }

	void toggleExportedDataVars() { m_showExportedDataVars = !m_showExportedDataVars; }
	void toggleExportedFunctions() { m_showExportedFunctions = !m_showExportedFunctions; }
	void toggleLocalFunctions() { m_showLocalFunctions = !m_showLocalFunctions; }
	void toggleLocalDataVars() { m_showLocalDataVars = !m_showLocalDataVars; }
	void toggleImports() { m_showImports = !m_showImports; }

	bool getShowExportedFunctions() const  { return m_showExportedFunctions; }
	bool getShowExportedDataVars() const  { return m_showExportedDataVars; }
	bool getShowLocalFunctions() const  { return m_showLocalFunctions; }
	bool getShowLocalDataVars() const  { return m_showLocalDataVars; }
	bool getShowImports() const  { return m_showImports; }

	bool getShowMangled() const { return m_displayMangled; }
	void setShowMangled(bool show) { m_displayMangled = show; }

	void sortSymbols(SortType type);
	void setSortType(SortType type) { m_sortType = type; }
	SortType getSortType() const { return m_sortType; }
	NamedObject getCurrentSym() const { return m_currentSym; }

	bool checkTriggerFullUpdate();

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
	SymbolListDelegate* m_delegate;
	QTimer* m_updateTimer;
	bool m_disableScrollToFunction;

	bool m_showExportedFunctions;
	bool m_showExportedDataVars;
	bool m_showLocalFunctions;
	bool m_showLocalDataVars;
	bool m_showImports;
	std::string m_filter;
	SymbolListModel::NamedObject m_index;
	SymbolListModel::NamedObject m_topIndex;
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

	bool getShowExportedFunctions() const { return m_list->getShowExportedFunctions(); }
	bool getShowExportedDataVars() const { return m_list->getShowExportedDataVars(); }
	bool getShowLocalFunctions() const { return m_list->getShowLocalFunctions(); }
	bool getShowLocalDataVars() const { return m_list->getShowLocalDataVars(); }
	bool getShowImports() const { return m_list->getShowImports(); }
	bool getShowMangled() const { return m_list->getShowMangled(); }

	void toggleExportedFunctions() { m_list->toggleExportedFunctions(); }
	void toggleExportedDataVars() { m_list->toggleExportedDataVars(); }
	void toggleLocalFunctions() { m_list->toggleLocalFunctions(); }
	void toggleLocalDataVars() { m_list->toggleLocalDataVars(); }
	void toggleImports() { m_list->toggleImports(); }

protected:
	virtual void focusOutEvent(QFocusEvent* event) override;
	virtual void keyPressEvent(QKeyEvent* event) override;

private Q_SLOTS:
	void goToSymbol(const QModelIndex& i);
	void updateTimerEvent();
	void savePosition();
	void restorePosition();
	void saveIndex(const QModelIndex& index);
	void clearIndex(const QModelIndex& index);
};
