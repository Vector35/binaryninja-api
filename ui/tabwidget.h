#pragma once

#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTabBar>
#include <QtWidgets/QStackedWidget>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QAbstractScrollArea>
#include <QtWidgets/QStylePainter>
#include <QtWidgets/QRubberBand>
#include <QtGui/QMouseEvent>
#include "uitypes.h"


class DockableTabWidget;

class BINARYNINJAUIAPI DockableTabCollection
{
	std::set<DockableTabWidget*> m_containers;

public:
	void registerContainer(DockableTabWidget* widget);
	void unregisterContainer(DockableTabWidget* widget);

	const std::set<DockableTabWidget*>& containers() const { return m_containers; }
};

class BINARYNINJAUIAPI TabDragIndicator: public QWidget
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

class BINARYNINJAUIAPI DockableTabBar: public QAbstractScrollArea
{
	Q_OBJECT

	struct TabInfo
	{
		QString title;
		QString toolTip;
		QRect tabRect, closeButtonRect, closeIconRect;
	};

	DockableTabCollection* m_collection;
	std::vector<TabInfo> m_tabs;
	int m_active = -1;

	bool m_mouseInside = false;
	int m_closeButtonHover = -1;
	int m_closeButtonDown = -1;

	std::optional<QPoint> m_tabDragStart;
	TabDragIndicator* m_tabDragIndicator = nullptr;
	DockableTabBar* m_tabDragTarget = nullptr;
	int m_tabDragWidth;
	int m_tabDragTargetIndex = -1;
	bool m_tabDragNewWindow = false;
	QRubberBand* m_tabDropIndicator = nullptr;

	int m_placeholderIndex = -1;
	int m_placeholderWidth;
	QRect m_placeholderRect;

	QTimer* m_timer;

	QStyleOptionTab styleForTab(int idx, const TabInfo& info) const;
	QSize sizeForTab(const QStyleOptionTab& tabStyle, const TabInfo& info) const;
	int closeButtonSize() const;
	void updateLayout();
	void paintTab(QStylePainter& p, const TabInfo& info, int i, const QRect& rect);

public:
	DockableTabBar(DockableTabCollection* collection);
	virtual ~DockableTabBar();

	int addTab(const QString& title);
	int insertTab(int idx, const QString& title);
	void removeTab(int idx);
	void setCurrentIndex(int idx);
	void setTabText(int idx, const QString& title);
	void setTabToolTip(int idx, const QString& toolTip);

	int count() const;
	int currentIndex() const;
	int tabAt(const QPoint& pt);
	QRect tabRect(int idx);
	QString tabText(int idx);
	QString tabToolTip(int idx);

	void ensureCurrentTabVisible();

Q_SIGNALS:
	void currentChanged(int idx);
	void tabCloseRequested(int idx);
	void tabMoved(int oldIdx, int newIdx);
	void newWindowForTab(int idx, QRect rectHint);
	void reparentTab(int oldIdx, DockableTabWidget* target, int newIdx);

private Q_SLOTS:
	void underMouseTimerEvent();

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

class BINARYNINJAUIAPI DockableTabWidget: public QWidget
{
	Q_OBJECT

	DockableTabCollection* m_collection;
	DockableTabBar* m_bar;
	QHBoxLayout* m_barLayout;
	QStackedWidget* m_widgets;

	void addReparentedTab(DockableTabWidget* source, int idx, QWidget* widget,
		const QString& title, const QString& toolTip);

public:
	DockableTabWidget(DockableTabCollection* collection);

	int addTab(QWidget* widget, const QString& title);
	int insertTab(int idx, QWidget* widget, const QString& title);
	void removeTab(int idx);

	int count();
	int currentIndex();
	QWidget* currentWidget();
	QWidget* widget(int idx);
	DockableTabBar* tabBar() const { return m_bar; }
	QString tabText(int idx);
	int indexOf(QWidget* widget);

	void setCurrentIndex(int idx);
	void setTabText(int idx, const QString& title);

	void setCornerWidget(QWidget* widget, Qt::Corner corner = Qt::TopRightCorner);

	virtual QSize sizeHint() const override;

protected:
	virtual void paintEvent(QPaintEvent* event) override;

Q_SIGNALS:
	void tabCloseRequested(int idx);
	void currentChanged(int idx);
	void tabMoved(int oldIdx, int newIdx);
	void newWindowForTab(int idx, QRect rectHint);
	void tabRemovedForReparent(int oldIdx, QWidget* widget, DockableTabWidget* target, int newIdx);
	void tabAddedForReparent(int idx, DockableTabWidget* source);

private Q_SLOTS:
	void tabBarCurrentChanged(int idx);
	void tabBarCloseRequested(int idx);
	void tabBarTabMoved(int oldIdx, int newIdx);
	void tabBarNewWindowForTab(int idx, QRect rectHint);
	void reparentTab(int oldIdx, DockableTabWidget* target, int newIdx);
};
