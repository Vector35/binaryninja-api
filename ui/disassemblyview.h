#pragma once

#include <QtWidgets/QAbstractScrollArea>
#include <QtCore/QPointer>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QLabel>
#include <mutex>
#include <optional>
#include "binaryninjaapi.h"
#include "viewframe.h"
#include "instructionedit.h"
#include "render.h"
#include "progressindicator.h"
#include "commentdialog.h"
#include "menus.h"
#include "statusbarwidget.h"
#include "flowgraphwidget.h"
#include "ilchooser.h"

#define FUNCTION_UPDATE_CHECK_INTERVAL 100

/*!

	\defgroup disassemblyview
 	\ingroup uiapi
*/

/*!

    \ingroup disassemblyview
*/
class BINARYNINJAUIAPI DisassemblyHistoryEntry : public FlowGraphHistoryEntry
{
	BinaryNinja::FunctionViewType m_graphType;

  public:
	const BinaryNinja::FunctionViewType& getGraphType() const { return m_graphType; }
	void setGraphType(const BinaryNinja::FunctionViewType& type) { m_graphType = type; }

	virtual Json::Value serialize() const override;
	virtual bool deserialize(const Json::Value& value) override;
};

class DisassemblyContainer;
/*!

    \ingroup disassemblyview
*/
class BINARYNINJAUIAPI DisassemblyView : public FlowGraphWidget
{
	Q_OBJECT

	friend class DisassemblyFunctionHeader;

  public:
	explicit DisassemblyView(DisassemblyContainer* parent, BinaryViewRef data, FunctionRef func = nullptr,
	    bool navToAddr = false, uint64_t addr = 0);

	virtual void notifyRefresh() override;

	virtual void updateFonts() override;

	virtual bool navigate(uint64_t pos) override;
	virtual bool navigateToFunction(FunctionRef func, uint64_t pos) override;
	virtual bool navigateToViewLocation(const ViewLocation& viewLocation, bool center = false) override;

	virtual BinaryNinja::Ref<HistoryEntry> getHistoryEntry() override;
	virtual void navigateToHistoryEntry(BinaryNinja::Ref<HistoryEntry> entry) override;

	virtual StatusBarWidget* getStatusBarWidget() override;
	virtual ViewPaneHeaderSubtypeWidget* getHeaderSubtypeWidget() override;
	virtual QWidget* getHeaderOptionsWidget() override;

	virtual BinaryNinja::FunctionViewType getILViewType() override { return m_ilViewType; };
	virtual void setILViewType(const BinaryNinja::FunctionViewType& ilViewType) override;

	void setOption(BNDisassemblyOption option, bool state = true);
	void toggleOption(BNDisassemblyOption option);
	void setAddressMode(std::optional<BNDisassemblyAddressMode> mode, std::optional<bool> hex, std::optional<bool> withName);
	void setCallParamHints(BNDisassemblyCallParameterHints hints);
	void setDisplayedFileName();
	void setAddressBaseOffset(bool toHere);

	virtual DisassemblySettingsRef getDisassemblySettings() override;
	virtual void setDisassemblySettings(DisassemblySettingsRef settings) override;

	virtual void notifyUpdateInProgress(FunctionRef func) override;
	virtual void onFunctionSelected(FunctionRef func) override;
	virtual void onHighlightChanged(const HighlightTokenState& highlight) override;

	static void registerActions();

  private:
	class DisassemblyViewOptionsWidget : public MenuHelper
	{
	  public:
		DisassemblyViewOptionsWidget(DisassemblyView* parent);

	  protected:
		virtual void mousePressEvent(QMouseEvent* event);
		virtual void showMenu();

	  private:
		DisassemblyView* m_view;
	};

	class DisassemblyViewOptionsIconWidget : public QWidget
	{
	  public:
		DisassemblyViewOptionsIconWidget(DisassemblyView* parent);

	  private:
		DisassemblyView* m_view;
		ContextMenuManager* m_contextMenuManager;
		Menu m_menu;

		void showMenu();
	};

	class DisassemblyViewStatusBarWidget : public StatusBarWidget
	{
	  public:
		DisassemblyViewStatusBarWidget(DisassemblyView* parent);
		virtual void updateStatus() override;

	  private:
		DisassemblyView* m_view;
		ILChooserWidget* m_chooser;
		DisassemblyViewOptionsWidget* m_options;
	};

	void bindActions();
	static void addOptionsMenuActions(Menu& menu);

	BinaryNinja::FunctionViewType m_ilViewType;
	std::set<BNDisassemblyOption> m_options;
	BNDisassemblyAddressMode m_addressMode;
	BNDisassemblyCallParameterHints m_callParamHints;
	DisassemblyContainer* m_container;
	SettingsRef m_settings;

  private Q_SLOTS:
	void viewInHexEditor();
	void viewInLinearDisassembly();
	void viewInDecompiler();
	void cycleILView(bool forward);
};

/*!

    \ingroup disassemblyview
*/
class GraphTypeLabel : public MenuHelper
{
	Q_OBJECT

	DisassemblyContainer* m_container;
	uint64_t m_paletteCacheKey = 0;

	void updateCustomPalette();

  public:
	GraphTypeLabel(QWidget* parent, DisassemblyContainer* container);

  protected:
	void paintEvent(QPaintEvent* event) override;
	void showMenu() override;
};

/*!

    \ingroup disassemblyview
*/
class BINARYNINJAUIAPI DisassemblyFunctionHeader : public QWidget
{
	Q_OBJECT

	DisassemblyContainer* m_container;

	BinaryViewRef m_data;
	FunctionRef m_func;

	QProgressIndicator* m_updateIndicator;
	GraphTypeLabel* m_graphType = nullptr;

	RenderContext m_render;
	std::vector<BinaryNinja::DisassemblyTextLine> m_lines;
	size_t m_width;
	HighlightTokenState m_highlight;

	void adjustSize(int width, int height);

  protected:
	virtual void paintEvent(QPaintEvent* event) override;
	virtual void resizeEvent(QResizeEvent* event) override;

	virtual void mousePressEvent(QMouseEvent* event) override;
	virtual void mouseDoubleClickEvent(QMouseEvent* event) override;

  public:
	DisassemblyFunctionHeader(DisassemblyContainer* parent, BinaryViewRef data);

	void updateFonts();
	void setCurrentFunction(FunctionRef func);
	void setILViewType(const BinaryNinja::FunctionViewType& ilViewType);
	void setHighlightToken(const HighlightTokenState& state);
	void notifyRefresh();

	virtual QSize sizeHint() const override;
};

/*!

    \ingroup disassemblyview
*/
class BINARYNINJAUIAPI DisassemblyContainer : public QWidget, public ViewContainer
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
	void setILViewType(const BinaryNinja::FunctionViewType& ilViewType);
	void setHeaderHighlightToken(const HighlightTokenState& state);

  protected:
	virtual void focusInEvent(QFocusEvent* event) override;

  private Q_SLOTS:
	void linkActivatedEvent(const QString& link);
};

/*!

    \ingroup disassemblyview
*/
class DisassemblyViewType : public ViewType
{
	static DisassemblyViewType* m_instance;

  public:
	DisassemblyViewType();
	virtual int getPriority(BinaryViewRef data, const QString& filename);
	virtual QWidget* create(BinaryViewRef data, ViewFrame* viewFrame);
	static void init();
};
