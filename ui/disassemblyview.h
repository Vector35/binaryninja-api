#pragma once

#include <QtWidgets/QAbstractScrollArea>
#include <QtCore/QPointer>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QLabel>
#include <mutex>
#include "binaryninjaapi.h"
#include "viewframe.h"
#include "instructionedit.h"
#include "render.h"
#include "progressindicator.h"
#include "commentdialog.h"
#include "menus.h"
#include "statusbarwidget.h"
#include "flowgraphwidget.h"

#define FUNCTION_UPDATE_CHECK_INTERVAL 100

class BINARYNINJAUIAPI DisassemblyHistoryEntry: public FlowGraphHistoryEntry
{
	BNFunctionGraphType m_graphType;

public:
	BNFunctionGraphType getGraphType() const { return m_graphType; }
	void setGraphType(BNFunctionGraphType type) { m_graphType = type; }
};

class DisassemblyContainer;

class BINARYNINJAUIAPI DisassemblyView: public FlowGraphWidget
{
	Q_OBJECT

friend class DisassemblyFunctionHeader;

public:
	explicit DisassemblyView(DisassemblyContainer* parent, BinaryViewRef data, FunctionRef func = nullptr,
		bool navToAddr = false, uint64_t addr = 0);

	virtual bool navigate(uint64_t pos) override;
	virtual bool navigateToFunction(FunctionRef func, uint64_t pos) override;

	virtual HistoryEntry* getHistoryEntry() override;
	virtual void navigateToHistoryEntry(HistoryEntry* entry) override;

	virtual StatusBarWidget* getStatusBarWidget() override;

	void setGraphType(BNFunctionGraphType type);
	BNFunctionGraphType getGraphType() { return m_graphType; };
	void setOption(BNDisassemblyOption option, bool state = true);
	void toggleOption(BNDisassemblyOption option);

	DisassemblySettingsRef getSettings();

	virtual void notifyUpdateInProgress(FunctionRef func) override;
	virtual void onFunctionSelected(FunctionRef func) override;
	virtual void onHighlightChanged(const HighlightTokenState& highlight) override;

	static void registerActions();

private:
	class DisassemblyViewOptionsWidget: public MenuHelper
	{
	public:
		DisassemblyViewOptionsWidget(DisassemblyView* parent);

	protected:
		virtual void mousePressEvent(QMouseEvent* event);
		virtual void showMenu();

	private:
		DisassemblyView* m_view;
	};

	class DisassemblyViewStatusBarWidget: public StatusBarWidget
	{
	public:
		DisassemblyViewStatusBarWidget(DisassemblyView* parent);
		virtual void updateStatus() override;

	private:
		DisassemblyView* m_view;
		DisassemblyViewOptionsWidget* m_options;
	};

	void bindActions();

	BNFunctionGraphType m_graphType;
	std::set<BNDisassemblyOption> m_options;
	DisassemblyContainer* m_container;
	SettingsRef m_settings;

private Q_SLOTS:
	void viewInHexEditor();
	void viewInLinearDisassembly();
	void viewInDecompiler();
	void cycleILView(bool forward);
};


class GraphTypeLabel: public MenuHelper
{
	Q_OBJECT

	DisassemblyContainer* m_container;

public:
	GraphTypeLabel(QWidget* parent, DisassemblyContainer* container);

protected:
	virtual void showMenu();
};


class BINARYNINJAUIAPI DisassemblyFunctionHeader: public QWidget
{
	Q_OBJECT

	DisassemblyContainer* m_container;

	BinaryViewRef m_data;
	FunctionRef m_func;

	QProgressIndicator* m_updateIndicator;
	QTimer* m_updateTimer;
	GraphTypeLabel* m_graphType;

	RenderContext m_render;
	std::vector<BinaryNinja::DisassemblyTextLine> m_lines;
	size_t m_width;
	HighlightTokenState m_highlight;

	void adjustSize(int width, int height);

private Q_SLOTS:
	void updateTimerEvent();

protected:
	virtual void paintEvent(QPaintEvent* event) override;
	virtual void resizeEvent(QResizeEvent* event) override;

	virtual void mousePressEvent(QMouseEvent* event) override;
	virtual void mouseDoubleClickEvent(QMouseEvent* event) override;

public:
	DisassemblyFunctionHeader(DisassemblyContainer* parent, BinaryViewRef data);

	void updateFonts();
	void setCurrentFunction(FunctionRef func);
	void setGraphType(BNFunctionGraphType graphType);
	void setHighlightToken(const HighlightTokenState& state);

	virtual QSize sizeHint() const override;
};

class BINARYNINJAUIAPI DisassemblyContainer: public QWidget, public ViewContainer
{
	Q_OBJECT

	ViewFrame* m_viewFrame;
	DisassemblyView* m_view;
	DisassemblyFunctionHeader* m_funcHeader;
	QWidget* m_analysisWarning;
	QLabel* m_analysisWarningText;

public:
	explicit DisassemblyContainer(QWidget* parent, BinaryViewRef data, ViewFrame* view, FunctionRef func = nullptr,
		bool navToAddr = false, uint64_t addr = 0);
	virtual View* getView() override { return m_view; }
	ViewFrame* getViewFrame() { return m_viewFrame; }

	DisassemblyView* getDisassembly() const { return m_view; }
	DisassemblyFunctionHeader* getFunctionHeader() const { return m_funcHeader; }

	void updateFonts();
	void refreshHeader(FunctionRef func);
	void setCurrentFunction(FunctionRef func);
	void setGraphType(BNFunctionGraphType graphType);
	void setHeaderHighlightToken(const HighlightTokenState& state);

protected:
	virtual void focusInEvent(QFocusEvent* event) override;

private Q_SLOTS:
	void linkActivatedEvent(const QString& link);
};

class DisassemblyViewType: public ViewType
{
	static DisassemblyViewType* m_instance;

public:
	DisassemblyViewType();
	virtual int getPriority(BinaryViewRef data, const QString& filename);
	virtual QWidget* create(BinaryViewRef data, ViewFrame* viewFrame);
	static void init();
};
