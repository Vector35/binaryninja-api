#pragma once

#include <QtWidgets/QListView>
#include <QtCore/QAbstractItemModel>
#include <QtCore/QTimer>
#include <QtWidgets/QLineEdit>
#include <vector>
#include <mutex>
#include "binaryninjaapi.h"
#include "viewframe.h"
#include "filter.h"
#include "uicontext.h"

#define FUNCTION_LIST_UPDATE_INTERVAL 250

class BINARYNINJAUIAPI FunctionListModel: public QAbstractItemModel, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

	enum FunctonListUpdateType
	{
		AddedToFunctionList,
		RemovedFromFunctionList,
		UpdatedInFunctionList
	};

	struct FunctionListUpdateEvent
	{
		FunctionRef func;
		FunctonListUpdateType type;
	};

	struct NamedFunction
	{
		FunctionRef func;
		std::string name;
		bool named;
	};

	class FunctionListUpdate: public BinaryNinja::RefCountObject
	{
		std::mutex m_mutex;
		bool m_valid;
		FunctionListModel* m_model;

	public:
		FunctionListUpdate(FunctionListModel* model);
		void start();
		void abort();
	};

	QWidget* m_funcList;
	ViewFrame* m_view;
	BinaryViewRef m_data;
	std::vector<FunctionRef> m_funcs;
	std::vector<NamedFunction> m_allFuncs;
	FunctionRef m_currentFunc;
	std::string m_filter;

	std::mutex m_updateMutex;
	std::vector<FunctionListUpdateEvent> m_updates;
	bool m_fullUpdate;

	BinaryNinja::Ref<FunctionListUpdate> m_backgroundUpdate;
	volatile bool m_backgroundUpdateComplete;
	std::vector<FunctionRef> m_backgroundUpdateFuncs;


	static bool functionComparison(const FunctionRef& a, const FunctionRef& b);
	static bool allFunctionComparison(const NamedFunction& a, const NamedFunction& b);

public:
	FunctionListModel(QWidget* parent, ViewFrame* view, BinaryViewRef data);
	virtual ~FunctionListModel();

	virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
	virtual QModelIndex parent(const QModelIndex& i) const override;
	virtual bool hasChildren(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	virtual int columnCount(const QModelIndex& parent) const override;
	virtual QVariant data(const QModelIndex& i, int role) const override;

	virtual void OnAnalysisFunctionAdded(BinaryNinja::BinaryView* data, BinaryNinja::Function* func) override;
	virtual void OnAnalysisFunctionRemoved(BinaryNinja::BinaryView* data, BinaryNinja::Function* func) override;
	virtual void OnAnalysisFunctionUpdated(BinaryNinja::BinaryView* data, BinaryNinja::Function* func) override;

	void updateFonts();
	bool setCurrentFunction(FunctionRef func);
	QModelIndex findFunction(FunctionRef func);
	QModelIndex findCurrentFunction();
	FunctionRef getFunctionForIndex(int i);

	void updateFunctions();
	void backgroundUpdate();
	bool hasFunctions() const;

	void setFilter(const std::string& filter);
};

class BINARYNINJAUIAPI FunctionList: public QListView, public FilterTarget
{
	Q_OBJECT

	ViewFrame* m_view;
	BinaryViewRef m_data;
	FunctionListModel* m_list;
	QTimer* m_updateTimer;
	bool m_disableScrollToFunction;

public:
	FunctionList(QWidget* parent, ViewFrame* frame, BinaryViewRef data);

	void updateFonts();
	void setCurrentFunction(FunctionRef func);

	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void selectFirstItem() override;
	virtual void activateFirstItem() override;
	virtual void setFilter(const std::string& filter) override;

	bool hasFunctions();

	virtual void copy();
	virtual void paste();
	virtual bool canCopy();

protected:
	virtual void focusOutEvent(QFocusEvent* event) override;
	virtual void keyPressEvent(QKeyEvent* event) override;

private Q_SLOTS:
	void goToFunction(const QModelIndex& i);
	void updateTimerEvent();
};
