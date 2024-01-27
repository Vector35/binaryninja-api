#pragma once

#include <QtWidgets/QWidget>
#include <QtWidgets/QStackedWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QRubberBand>
#include "uicontext.h"
#include "clickablelabel.h"
#include "splitter.h"

class ViewFrame;
class FeatureMap;
class PaneHeader;
class PaneHeaderContainer;
class PaneHeaderFade;
class CloseButton;
class TabDragIndicator;
class SyncGroup;

/*!

	\defgroup pane Pane
 	\ingroup uiapi
*/

/*!

    \ingroup pane
*/
class BINARYNINJAUIAPI Pane : public QWidget
{
	Q_OBJECT

	QWidget* m_widget;
	PaneHeaderContainer* m_headerContainer = nullptr;
	PaneHeaderFade* m_headerFade = nullptr;
	PaneHeader* m_header = nullptr;
	CloseButton* m_closeButton = nullptr;
	bool m_active = false;
	QVBoxLayout* m_layout = nullptr;

  public:
	Pane(QWidget* widget);

	QWidget* widget() const { return m_widget; }
	virtual bool canSplitPane() const { return false; }
	virtual Pane* createSplitPane() { return nullptr; }
	virtual void updateStatus();
	virtual void focus();
	virtual QString title() = 0;
	void closePane();
	Pane* splitPane(Qt::Orientation orientation);
	void splitPane(Pane* pane, Qt::Edge edge);
	void moveToNewWindow();

	virtual void setIsSinglePane(bool isSinglePane);
	virtual void setIsActivePane(bool active);
	virtual Qt::Orientation defaultSplitDirection() const { return Qt::Horizontal; }
	virtual void setDefaultSplitDirection(Qt::Orientation orientation);

	void setWidget(QWidget* widget);

  protected:
	void init(PaneHeader* header);

  Q_SIGNALS:
	void paneCloseRequested();
	void paneSplitRequested(Pane* newPane, Qt::Edge edge);
	void movePane(Pane* target, Qt::Edge edge);
	void newWindowForPane(QScreen* screen, QPoint pos);
	void notifyViewChanged(ViewFrame* frame);

  public Q_SLOTS:
	void splitButtonClicked(Qt::Orientation orientation);
	void closeButtonClicked();
	void headerClicked();
	void headerResized(QSize size);
	void movePaneRequested(Pane* target, Qt::Edge edge);
	void newWindowForPaneRequested(QScreen* screen, QPoint pos);
};

/*!

    \ingroup pane
*/
class BINARYNINJAUIAPI SplitButton : public ClickableIcon
{
	Q_OBJECT

	Qt::Orientation m_defaultOrientation;
	bool m_mouseInside = false;
	bool m_inverted = false;

	void setIconForOrientation(Qt::Orientation orientation);
	void splitHorizontal();
	void splitVertical();

  public:
	SplitButton();

	void setDefaultOrientation(Qt::Orientation orientation);
	Qt::Orientation orientation() const;
	Qt::Orientation defaultOrientation() const { return m_defaultOrientation; }

  protected:
	virtual void enterEvent(QEnterEvent* event) override;
	virtual void leaveEvent(QEvent* event) override;
	virtual bool eventFilter(QObject* obj, QEvent* event) override;
	virtual void mousePressEvent(QMouseEvent* event) override;

  Q_SIGNALS:
	void splitWithDirection(Qt::Orientation orientation);
};

/*!

    \ingroup pane
*/
class BINARYNINJAUIAPI PaneHeader : public QWidget
{
	Q_OBJECT

	Pane* m_owner = nullptr;
	std::optional<QPoint> m_dragStart;
	TabDragIndicator* m_dragIndicator = nullptr;
	bool m_dragNewWindow = false;
	Pane* m_dropTarget = nullptr;
	Qt::Edge m_dropEdge = Qt::RightEdge;
	QRubberBand* m_dropIndicator = nullptr;

  public:
	PaneHeader();

	void setOwner(Pane* pane) { m_owner = pane; }

  protected:
	virtual void mousePressEvent(QMouseEvent* event) override;
	virtual void mouseMoveEvent(QMouseEvent* event) override;
	virtual void mouseReleaseEvent(QMouseEvent* event) override;

  Q_SIGNALS:
	void paneCloseRequested();
	void paneSplitRequested(Qt::Orientation orientation);
	void movePane(Pane* target, Qt::Edge edge);
	void newWindowForPane(QScreen* screen, QPoint pos);
	void headerClicked();
};

/*!

    \ingroup pane
*/
class BINARYNINJAUIAPI PaneHeaderContainer : public QWidget
{
	Q_OBJECT

public:
	PaneHeaderContainer() {}

protected:
	virtual void resizeEvent(QResizeEvent* event) override;

Q_SIGNALS:
	void resize(QSize size);
};

/*!

    \ingroup pane
*/
class BINARYNINJAUIAPI PaneHeaderFade : public QWidget
{
	Q_OBJECT

	bool m_active = false;

public:
	PaneHeaderFade(QWidget* parent);
	void setActive(bool active);

protected:
	virtual void paintEvent(QPaintEvent* event) override;
};

class ViewFrame;
class ViewPaneHeader;

/*!

    \ingroup pane
*/
class BINARYNINJAUIAPI ViewPane : public Pane
{
	Q_OBJECT

	ViewFrame* m_frame;
	UIActionHandler m_actionHandler;
	ViewPaneHeader* m_header;

  public:
	ViewPane(ViewFrame* frame);

	ViewFrame* viewFrame() const { return m_frame; }
	virtual bool canSplitPane() const override { return true; }
	virtual Pane* createSplitPane() override;
	virtual void updateStatus() override;
	virtual Qt::Orientation defaultSplitDirection() const override;
	virtual void setDefaultSplitDirection(Qt::Orientation orientation) override;
	virtual void focus() override;
	virtual QString title() override;

#ifndef BINARYNINJAUI_BINDINGS
	void recreateViewFrame(std::map<SyncGroup*, ViewLocation>& locations);
#endif
	void sendViewChange();

  private Q_SLOTS:
	void viewChanged(ViewFrame* frame);
	void viewChangeRequested(QString type);
};

class DataTypeList;
class ViewList;
class SyncGroupWidget;

/*!

    \ingroup pane
*/
class BINARYNINJAUIAPI ViewPaneHeaderSubtypeWidget : public QWidget
{
	Q_OBJECT

  public:
	ViewPaneHeaderSubtypeWidget() {}
	virtual void updateStatus() = 0;
};

/*!

    \ingroup pane
*/
class BINARYNINJAUIAPI ViewPaneHeader : public PaneHeader
{
	Q_OBJECT

	ViewPane* m_owner;
	DataTypeList* m_dataTypeList;
	ViewList* m_viewList;
	SyncGroupWidget* m_syncGroup;

	View* m_subtypeView = nullptr;
	ViewPaneHeaderSubtypeWidget* m_subtypeWidget = nullptr;
	QWidget* m_optionsWidget = nullptr;
	QStackedWidget* m_subtypeWidgetContainer;
	QStackedWidget* m_optionsWidgetContainer;

	SplitButton* m_splitButton;

  public:
	ViewPaneHeader(ViewPane* owner, UIActionHandler* handler);

	void updateStatus();
	Qt::Orientation defaultSplitDirection() const;
	void setDefaultSplitDirection(Qt::Orientation orientation);
	void setViewFrame(ViewFrame* frame);

  Q_SIGNALS:
	void viewChanged(QString type);

  private Q_SLOTS:
	void splitButtonClicked();
	void splitButtonClickedWithDirection(Qt::Orientation orientation);
	void viewChangeRequested(QString type);
	void updateViewType(ViewFrame* frame);
};

/*!

    \ingroup pane
*/
class BINARYNINJAUIAPI WidgetPane : public Pane
{
	Q_OBJECT

	QString m_title;

  public:
	WidgetPane(QWidget* widget, QString title);
	virtual QString title() override { return m_title; }
	virtual void updateStatus() override;

  Q_SIGNALS:
	void updateWidgetStatus();
};

/*!

    \ingroup pane
*/
class BINARYNINJAUIAPI WidgetPaneHeader : public PaneHeader
{
	Q_OBJECT

	QString m_title;

  public:
	WidgetPaneHeader(const QString& title);

  protected:
	virtual void paintEvent(QPaintEvent* event) override;
};

class SplitPaneWidget;

/*!

    \ingroup pane
*/
class BINARYNINJAUIAPI SplitPaneContainer : public QWidget
{
	Q_OBJECT

	Pane* m_pane = nullptr;
	Splitter* m_splitter = nullptr;
	SplitPaneContainer* m_parent = nullptr;
	std::vector<SplitPaneContainer*> m_children;
	Pane* m_currentChild = nullptr;
	ViewPane* m_currentViewPane = nullptr;
	QVBoxLayout* m_layout;
	FileContext* m_fileContext = nullptr;

	SplitPaneContainer(const std::vector<SplitPaneContainer*>& children, Qt::Orientation orientation);

	void removeChild(SplitPaneContainer* child);
	void promoteChild(SplitPaneContainer* child);
	void updateDefaultSplitDirectionForColumnCount(uint64_t count);
	void removePaneForRelocation();
	void emitNewWindowForPane(SplitPaneWidget* paneWidget, QRect rect);
	void openForColumnCount(Pane* pane, Qt::Orientation primaryDirection, uint64_t count);
	void deactivateIfCurrent(Pane* pane);
	void notifyCurrentChanged(Pane* pane);

  public:
	SplitPaneContainer(Pane* initial);
	Pane* currentPane() const { return m_currentChild; }
	ViewPane* currentViewPane() const { return m_currentViewPane; }
	void notifyFocused();
	void updateStatus();

	void enumeratePanes(const std::function<void(Pane*)>& func);
	void enumerateViewPanes(const std::function<void(ViewPane*)>& func);

	bool isSinglePane();
	bool canSplitCurrentPane();
	void closeCurrentPane();
	Pane* splitCurrentPane(Qt::Orientation orientation);
	Qt::Orientation defaultSplitDirection() const;
	void nextPane();
	void prevPane();
	void focusPaneForEdge(Qt::Edge edge);
	void newWindowForCurrentPane();
	bool canMoveCurrentPaneToNewWindow();

	SplitPaneContainer* root();
	static SplitPaneContainer* containerForWidget(QWidget* widget);

	FileContext* fileContext() const { return m_fileContext; }
	void setFileContext(FileContext* fileContext) { m_fileContext = fileContext; }

	void open(Pane* pane, Qt::Orientation primaryDirection = Qt::Vertical);

	QVariantMap layoutPersistenceInfo() const;
	void applyPersistedLayout(const QVariantMap&);

#ifndef BINARYNINJAUI_BINDINGS
	QVariantMap serializeLayout();
	void deserializeLayout(const QVariantMap& layout, std::map<ViewFrame*, ViewLocation>& locations);
	void aboutToCloseViewFrames();
	void recreateViewFrames(std::map<SyncGroup*, ViewLocation>& locations);
#endif

Q_SIGNALS:
	void paneClosed(Pane* pane);
	void currentChanged(Pane* pane);
	void layoutChanged();
	void notifyViewChanged(ViewFrame* frame);
	void lastPaneClosed();
	void newWindowForPane(SplitPaneWidget* paneWidget, QRect rect);

  private Q_SLOTS:
	void paneCloseRequested();
	void paneSplitRequested(Pane* newPane, Qt::Edge edge);
	void movePane(Pane* target, Qt::Edge edge);
	void newWindowForPaneRequested(QScreen* screen, QPoint pos);
	void paneViewChanged(ViewFrame* frame);
	void childPaneClosed(Pane* pane);
	void childLayoutChanged();
	void childViewChanged(ViewFrame* frame);
};

/*!

    \ingroup pane
*/
class BINARYNINJAUIAPI SplitPaneWidget : public QWidget
{
	Q_OBJECT

	SplitPaneContainer* m_container;

	QStackedWidget* m_featureMapContainer;
	std::map<BinaryViewRef, FeatureMap*> m_featureMaps;
	Splitter* m_featureMapSplitter;
	bool m_rightSideFeatureMap = true;

	UIActionHandler m_actionHandler;

	std::map<ViewFrame*, ViewLocation> m_locations;

	void bindActions();

  public:
	SplitPaneWidget(Pane* initial, FileContext* fileContext);
	Pane* currentPane() const;
	ViewPane* currentViewPane() const;
	ViewFrame* currentViewFrame() const;
	SplitPaneContainer* container() const { return m_container; }
	FileContext* fileContext() const { return m_container->fileContext(); }

	void enumeratePanes(const std::function<void(Pane*)>& func);
	void enumerateViewPanes(const std::function<void(ViewPane*)>& func);
	Pane* paneAt(const QPoint& pos);

	void createFeatureMap();
	void recreateFeatureMaps();
	void refreshFeatureMap();
	void updateFeatureMapLocation(const ViewLocation& location);
	BinaryViewRef getCurrentBinaryView();

	void updateStatus();

	bool isSinglePane();
	bool canSplitCurrentPane();
	void closeCurrentPane();
	Pane* splitCurrentPane(Qt::Orientation orientation);
	Qt::Orientation defaultSplitDirection() const;
	void nextPane();
	void prevPane();
	void focusPaneForEdge(Qt::Edge edge);
	void newWindowForCurrentPane();
	bool canMoveCurrentPaneToNewWindow();

	QString getTabName();

	void open(Pane* pane, Qt::Orientation primaryDirection = Qt::Vertical);

	bool closeRequest();
	void closing();

#ifndef BINARYNINJAUI_BINDINGS
	bool hasInitialLocationState() { return !m_locations.empty(); }
	void applyInitialLocationState();
	QVariantMap serializeLayout();
	void deserializeLayout(const QVariantMap& layout);
	void recreateViewFrames(std::map<SyncGroup*, ViewLocation>& locations);
#endif

	static void registerActions();

  Q_SIGNALS:
	void paneClosed(Pane* pane);
	void currentChanged(Pane* pane);
	void layoutChanged();
	void notifyViewChanged(ViewFrame* frame);
	void newWindowForPane(SplitPaneWidget* paneWidget, QRect rect);

  private Q_SLOTS:
	void containerPaneClosed(Pane* pane);
	void containerCurrentChanged(Pane* pane);
	void containerLayoutChanged();
	void containerNotifyViewChanged(ViewFrame* frame);
	void containerLastPaneClosed();
	void containerNewWindowForPane(SplitPaneWidget* paneWidget, QRect rect);
	void featureMapSplitterMoved();
};
