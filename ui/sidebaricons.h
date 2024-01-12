#pragma once

#include <QtWidgets/QWidget>
#include <QtWidgets/QRubberBand>

class Sidebar;
class SidebarWidgetType;
class SidebarWidgetContainer;

/*!
    \ingroup sidebar
*/
enum SidebarLocation
{
	LeftSide,
	RightSide,
};

/*!
    \ingroup sidebar
*/
struct BINARYNINJAUIAPI SidebarIconInfo
{
	SidebarWidgetType* type;
	SidebarWidgetLocation location;
	size_t index;
	QRect rect;
};

/*!
    \ingroup sidebar
*/
class BINARYNINJAUIAPI SidebarIconDragIndicator : public QWidget
{
	Q_OBJECT

	QImage m_image;
	QSize m_size;
	QPoint m_offset;

public:
	SidebarIconDragIndicator(QImage image, QSize size, QPoint pt, QPoint offset);
	void moveToMouse(QPoint pt);

	QSize size() const { return m_size; }
	QPoint offset() const { return m_offset; }

protected:
	virtual QSize sizeHint() const override;
	virtual QSize minimumSizeHint() const override;
	virtual void paintEvent(QPaintEvent* event) override;
};

/*!
    \ingroup sidebar
*/
class BINARYNINJAUIAPI SidebarIconsWidget : public QWidget
{
	Q_OBJECT

	Sidebar* m_sidebar;
	SidebarLocation m_location;
	SidebarWidgetType* m_hoverItem = nullptr;
	SidebarWidgetContainer* m_sideContainer = nullptr;
	SidebarWidgetContainer* m_bottomContainer = nullptr;

	std::optional<QPoint> m_dragStart;
	std::optional<SidebarIconInfo> m_dragItem;
	bool m_dragItemAsPlaceholder = false;
	SidebarIconsWidget* m_dragTargetSidebar = nullptr;
	Pane* m_dragTargetPane = nullptr;
	Qt::Edge m_dragTargetPaneEdge = Qt::LeftEdge;
	SidebarIconDragIndicator* m_dragIndicator = nullptr;
	QRubberBand* m_dropIndicator = nullptr;

	std::vector<SidebarWidgetType*> filterTypesForPlaceholder(const std::vector<SidebarWidgetType*>& types) const;
	std::optional<SidebarIconInfo> itemForY(int y) const;
	std::pair<SidebarWidgetLocation, size_t> findDropLocation(int y) const;
	QRect placeholderRect() const;
	bool shouldBeVisible() const;

private Q_SLOTS:
	void containerUpdated();

protected:
	virtual void paintEvent(QPaintEvent* event) override;
	virtual void mouseMoveEvent(QMouseEvent* event) override;
	virtual void mousePressEvent(QMouseEvent* event) override;
	virtual void mouseReleaseEvent(QMouseEvent* event) override;
	virtual void leaveEvent(QEvent* event) override;

public:
	SidebarIconsWidget(Sidebar* sidebar, SidebarLocation location);

	SidebarWidgetContainer* sideContainer() const { return m_sideContainer; }
	SidebarWidgetContainer* bottomContainer() const { return m_bottomContainer; }
	SidebarWidgetContainer* containerForLocation(SidebarWidgetLocation location) const;
	SidebarIconsWidget* other() const;
	void setContainers(SidebarWidgetContainer* sideContainer, SidebarWidgetContainer* bottomContainer);

	void updateTheme();
	void updateVisibility();
	void refreshMetrics();

Q_SIGNALS:
	void containerVisibilityChanged();
};
