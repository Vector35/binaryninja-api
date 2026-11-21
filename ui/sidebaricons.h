#pragma once

#include <QtWidgets/QWidget>

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
	bool m_dragActive = false;
	SidebarIconsWidget* m_dragTargetSidebar = nullptr;
	Pane* m_dragTargetPane = nullptr;
	Qt::Edge m_dragTargetPaneEdge = Qt::LeftEdge;

	void startIconDrag(const QPoint& pos);
	bool dragUpdateTarget(QWidget* window, const QPoint& pos);
	void dragClearTarget();

	friend class SidebarIconDragSession;

	std::vector<SidebarWidgetType*> filterTypesForPlaceholder(const std::vector<SidebarWidgetType*>& types) const;
	std::optional<SidebarIconInfo> itemForY(int y) const;
	std::pair<SidebarWidgetLocation, size_t> findDropLocation(int y) const;
	QRect placeholderRect() const;
	bool shouldBeVisible() const;
	bool shouldContainMoreIcon() const;

private Q_SLOTS:
	void containerUpdated();
	void contentClassificationChanged();

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

	void focusChanged(SidebarWidgetAndHeader* widget);

Q_SIGNALS:
	void containerVisibilityChanged();
};
