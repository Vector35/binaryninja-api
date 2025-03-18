#pragma once

#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTabBar>
#include <QtWidgets/QStackedWidget>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QAbstractScrollArea>
#include <QtWidgets/QStylePainter>
#include <QtWidgets/QRubberBand>
#include <QtWidgets/QSplitter>
#include <QtGui/QMouseEvent>
#include "uitypes.h"
#include "json/json.h"
#include "splitter.h"


class DockableTabWidget;

/*!

	\defgroup tabwidget TabWidget
 	\ingroup uiapi
*/

/*!

    \ingroup tabwidget
*/
class BINARYNINJAUIAPI DockableTabCollection : public QObject
{
	Q_OBJECT
	std::set<DockableTabWidget*> m_containers;

public:
	void registerContainer(DockableTabWidget* widget);
	void unregisterContainer(DockableTabWidget* widget);

	const std::set<DockableTabWidget*>& containers() const { return m_containers; }
};

/*!

    \ingroup tabwidget
*/
class BINARYNINJAUIAPI TabDragIndicator : public QWidget
{
	Q_OBJECT

	QPixmap m_pixmap;
	QImage m_newWindowImage;
	QSize m_size, m_currentSize;
	QPoint m_offset;
	bool m_newWindow;

  public:
	TabDragIndicator(QPixmap pixmap, QSize size, QPoint pt, QPoint offset, bool newWindow);
	void moveToMouse(QPoint pt);

	QPixmap pixmap() const { return m_pixmap; }
	QSize size() const { return m_size; }
	QPoint offset() const { return m_offset; }

  protected:
	virtual QSize sizeHint() const override;
	virtual QSize minimumSizeHint() const override;
	virtual void paintEvent(QPaintEvent* event) override;
};

/*!

    \ingroup tabwidget
*/
enum DockableTabInteractionState
{
	NoTabInteraction,
	MouseOverTab,
	MouseOverCloseButton,
	CloseButtonPressActive,
	CloseButtonPressInactive
};

/*!

    \ingroup tabwidget
*/
struct BINARYNINJAUIAPI DockableTabInfo
{
	QString title;
	QString toolTip;
	QRect tabRect, closeButtonRect, closeIconRect;
	bool modifiedIndicator;
	bool canClose;
	bool isDrag = false;
};

/*!

    \ingroup tabwidget
*/
class BINARYNINJAUIAPI DockableTabStyle
{
  public:
	virtual ~DockableTabStyle() {}
	virtual QSize sizeForTab(const QWidget* widget, const DockableTabInfo& info, int idx, int count, int active) const;
	virtual QRect closeButtonRect(
	    const QWidget* widget, const DockableTabInfo& info, int idx, int count, int active) const;
	virtual QRect closeIconRect(
	    const QWidget* widget, const DockableTabInfo& info, int idx, int count, int active) const;
	virtual void paintTab(const QWidget* widget, QStylePainter& p, const DockableTabInfo& info, int idx, int count,
	    int active, DockableTabInteractionState state, const QRect& rect) const;
	virtual void paintBase(const QWidget* widget, QStylePainter& p, const QRect& rect, const QRect& activeRect) const;
	virtual DockableTabStyle* duplicate();
};

/*!

    \ingroup tabwidget
*/
class BINARYNINJAUIAPI DefaultDockableTabStyle : public DockableTabStyle
{
	QStyleOptionTab styleForTab(
	    const QWidget* widget, const DockableTabInfo& info, int idx, int count, int active) const;
	int closeButtonSize(const QWidget* widget) const;

  public:
	virtual QSize sizeForTab(
	    const QWidget* widget, const DockableTabInfo& info, int idx, int count, int active) const override;
	virtual QRect closeButtonRect(
	    const QWidget* widget, const DockableTabInfo& info, int idx, int count, int active) const override;
	virtual QRect closeIconRect(
	    const QWidget* widget, const DockableTabInfo& info, int idx, int count, int active) const override;
	virtual void paintTab(const QWidget* widget, QStylePainter& p, const DockableTabInfo& info, int idx, int count,
	    int active, DockableTabInteractionState state, const QRect& rect) const override;
	virtual void paintBase(
	    const QWidget* widget, QStylePainter& p, const QRect& rect, const QRect& activeRect) const override;
	virtual DockableTabStyle* duplicate() override;
};

/*!

    \ingroup tabwidget
*/
class BINARYNINJAUIAPI DockableTabBar : public QAbstractScrollArea
{
	Q_OBJECT

	DockableTabCollection* m_collection;
	DockableTabStyle* m_style;
	std::vector<DockableTabInfo> m_tabs;
	int m_active = -1;
	bool m_canCreateNewWindow = false;
	bool m_canSplit = false;

	bool m_mouseInside = false;
	int m_tabHover = -1;
	int m_closeButtonHover = -1;
	int m_closeButtonDown = -1;

	std::optional<QPoint> m_tabDragStart;
	TabDragIndicator* m_tabDragIndicator = nullptr;
	DockableTabBar* m_tabDragTarget = nullptr;
	int m_tabDragWidth;
	int m_tabDragTargetIndex = -1;
	std::optional<Qt::Edge> m_tabDragSplitEdge;
	bool m_tabDragNewWindow = false;
	QRubberBand* m_tabDropIndicator = nullptr;

	int m_placeholderIndex = -1;
	int m_placeholderWidth;
	QRect m_placeholderRect;

	QTimer* m_timer;
	QTimer* m_hoverTimer;

	void updateLayout();

  public:
	DockableTabBar(DockableTabCollection* collection);
	virtual ~DockableTabBar();

	int addTab(const QString& title);
	int insertTab(int idx, const QString& title);
	void removeTab(int idx);
	void setCurrentIndex(int idx);
	void setTabText(int idx, const QString& title);
	void setTabToolTip(int idx, const QString& toolTip);
	void setTabModifiedIndicator(int idx, bool indicator);
	void setCanCloseTab(int idx, bool canClose);
	void setCanCreateNewWindow(bool canCreate);
	void setCanSplit(bool canSplit);

	int count() const;
	int currentIndex() const;
	int tabAt(const QPoint& pt);
	QRect tabRect(int idx);
	QString tabText(int idx);
	QString tabToolTip(int idx);
	bool tabModifiedIndicator(int idx);
	bool canCloseTab(int idx);
	bool canCreateNewWindow();
	bool canSplit();

	void ensureCurrentTabVisible();

	DockableTabStyle* tabStyle() const { return m_style; }
	void setTabStyle(DockableTabStyle* style);

  Q_SIGNALS:
	void currentChanged(int idx);
	void tabCloseRequested(int idx);
	void tabMoved(int oldIdx, int newIdx);
	void newWindowForTab(int idx, QRect rectHint);
	void reparentTab(int oldIdx, DockableTabWidget* target, int newIdx);
	void splitTab(int idx, Qt::Edge edge);

  private Q_SLOTS:
	void underMouseTimerEvent();
	void tabHoverTimerEvent();

  protected:
	virtual QSize sizeHint() const override;
	virtual QSize minimumSizeHint() const override;
	virtual void paintEvent(QPaintEvent* event) override;
	virtual void enterEvent(QEnterEvent* event) override;
	virtual void leaveEvent(QEvent* event) override;
	virtual void mouseMoveEvent(QMouseEvent* event) override;
	virtual void mousePressEvent(QMouseEvent* event) override;
	virtual void mouseReleaseEvent(QMouseEvent* event) override;
	virtual void resizeEvent(QResizeEvent* event) override;
	virtual void wheelEvent(QWheelEvent* event) override;
};

/*!

    \ingroup tabwidget
*/
class BINARYNINJAUIAPI DockableTabBarWithCornerWidget : public QWidget
{
	DockableTabBar* m_bar;
	QHBoxLayout* m_barLayout;
	Qt::Corner m_corner = Qt::TopRightCorner;
	QWidget* m_cornerWidget = nullptr;
	QWidget* m_cornerWidgetContainer = nullptr;

  protected:
	virtual void paintEvent(QPaintEvent* event) override;

  public:
	DockableTabBarWithCornerWidget(DockableTabBar* bar);
	DockableTabBar* tabBar() const { return m_bar; }
	void setCornerWidget(QWidget* widget, Qt::Corner corner = Qt::TopRightCorner, bool expanding = false);
	Qt::Corner corner() const { return m_corner; }
	QWidget* cornerWidget() const { return m_cornerWidget; }

};

/*!

    \ingroup tabwidget
*/
class BINARYNINJAUIAPI DockableTabWidget : public QWidget
{
	Q_OBJECT

	DockableTabCollection* m_collection;
	DockableTabBar* m_bar;
	DockableTabBarWithCornerWidget* m_cornerWidget;
	QStackedWidget* m_widgets;

	void addReparentedTab(DockableTabWidget* source, int idx, QWidget* widget, const QString& title,
	    const QString& toolTip, bool canClose);

  public:
	DockableTabWidget(DockableTabCollection* collection, DockableTabBar* bar = nullptr);

	int addTab(QWidget* widget, const QString& title);
	int insertTab(int idx, QWidget* widget, const QString& title);
	void removeTab(int idx);

	int count();
	int currentIndex();
	QWidget* currentWidget();
	QWidget* widget(int idx);
	DockableTabBar* tabBar() const { return m_bar; }
	QStackedWidget* container() const { return m_widgets; }
	DockableTabCollection* collection() const { return m_collection; }
	QString tabText(int idx);
	bool tabModifiedIndicator(int idx);
	bool canCloseTab(int idx);
	bool canCreateNewWindow();
	bool canSplit();
	int indexOf(QWidget* widget);

	void setCurrentIndex(int idx);
	void setTabText(int idx, const QString& title);
	void setTabToolTip(int idx, const QString& toolTip);
	void setTabModifiedIndicator(int idx, bool indicator);
	void setCanCloseTab(int idx, bool canClose);
	void setCanCreateNewWindow(bool canCreate);
	void setCanSplit(bool canSplit);

	void setCornerWidget(QWidget* widget, Qt::Corner corner = Qt::TopRightCorner, bool expanding = false);
	Qt::Corner corner() const;
	QWidget* cornerWidget() const;

	DockableTabStyle* tabStyle() const { return m_bar->tabStyle(); }
	void setTabStyle(DockableTabStyle* style);

	virtual QSize sizeHint() const override;

  Q_SIGNALS:
	void tabCloseRequested(int idx);
	void currentChanged(int idx);
	void tabMoved(int oldIdx, int newIdx);
	void newWindowForTab(int idx, QRect rectHint);
	void tabRemovedForReparent(int oldIdx, QWidget* widget, DockableTabWidget* target, int newIdx);
	void tabAddedForReparent(int idx, DockableTabWidget* source);
	void splitTab(int idx, Qt::Edge edge);

  private Q_SLOTS:
	void tabBarCurrentChanged(int idx);
	void tabBarCloseRequested(int idx);
	void tabBarTabMoved(int oldIdx, int newIdx);
	void tabBarNewWindowForTab(int idx, QRect rectHint);
	void tabBarSplitTab(int idx, Qt::Edge edge);
	void reparentTab(int oldIdx, DockableTabWidget* target, int newIdx);
};

class BINARYNINJAUIAPI FlexibleTabBar : public QWidget
{
	DockableTabBar* m_bar;

	QHBoxLayout* m_overallBarLayout;
	QHBoxLayout* m_barLayout;
	QHBoxLayout* m_leftLayout;
	QHBoxLayout* m_rightLayout;

public:
	enum FlexibleTabBarWidgetLocation {
		LeftCorner,
		RightCorner,
		AfterTabs
	};
	FlexibleTabBar(DockableTabBar* bar);
	void addWidget(QWidget* widget, FlexibleTabBarWidgetLocation corner);
	void insertWidget(int idx, QWidget* widget, FlexibleTabBarWidgetLocation corner);

protected:
	void paintEvent(QPaintEvent* event) override;
};

/*!

    \ingroup tabwidget
*/
class BINARYNINJAUIAPI SplitTabWidget : public QWidget
{
	Q_OBJECT

	DockableTabWidget* m_tabs = nullptr;
	Splitter* m_splitter = nullptr;
	SplitTabWidget* m_first = nullptr;
	SplitTabWidget* m_second = nullptr;
	QVBoxLayout* m_layout;

	SplitTabWidget(DockableTabWidget* tabs);
	SplitTabWidget(SplitTabWidget* first, SplitTabWidget* second, Qt::Orientation orientation);

	void splitTabInternal(QWidget* widget, QString title, bool canClose, Qt::Edge edge);
	void promoteChild(SplitTabWidget* child, SplitTabWidget* other);

	void enumerateTabTree(const std::function<void(SplitTabWidget*, QWidget*, QString)>& func);
	Json::Value savedLayoutObject() const;
	void restoreLayoutObject(const Json::Value& layout);
	void restoreLayoutObjectWithTabs(
	    const Json::Value& layout, std::map<QString, std::pair<DockableTabWidget*, QWidget*>>& tabWidgets);
	DockableTabWidget* findFirstTabWidget();
	void collapseEmptyTabs();

  public:
	SplitTabWidget(DockableTabCollection* collection);

	void addTab(QWidget* widget, const QString& title);
	bool removeTab(QWidget* widget);
	void setCanCloseTab(QWidget* widget, bool canClose);
	void enumerateTabs(const std::function<void(QWidget*)>& func);
	void selectWidget(QWidget* widget);
	bool isWidgetVisible(QWidget* widget);
	bool closeTab(QWidget* widget);
	void setTabSizes(const QList<int>& sizes);

	void setTabStyle(DockableTabStyle* style);

	void setCornerWidget(QWidget* widget, Qt::Corner corner = Qt::TopRightCorner, bool expanding = false);

	QString savedLayoutString() const;
	void restoreLayoutString(const QString& layout);

  Q_SIGNALS:
	void tabClosed(QWidget* widget);
	void currentChanged(QWidget* widget);
	void layoutChanged();
	void splitSizeChanged();

  private Q_SLOTS:
	void tabCloseRequested(int idx);
	void currentTabChanged(int idx);
	void splitTab(int idx, Qt::Edge edge);
	void tabRemovedForReparent(int oldIdx, QWidget* widget, DockableTabWidget* target, int newIdx);
	void childTabClosed(QWidget* widget);
	void childCurrentChanged(QWidget* widget);
	void childLayoutChanged();
};
