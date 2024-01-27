#pragma once

#include <QtWidgets/QWidget>
#include <QtCore/QSettings>
#include <vector>
#include <set>
#include <map>
#include "uicontext.h"

/*!
    \defgroup splitter Splitter
    \ingroup uiapi
*/

/*!
    \ingroup splitter
*/
enum SplitterWidgetSizingStyle
{
	RelativeWidgetSize,
	WidgetSizeInPoints
};

/*!
    \ingroup splitter
*/
struct BINARYNINJAUIAPI SplitterWidgetSizing
{
	SplitterWidgetSizingStyle style;
	float referenceSize;
	bool isDefault;
	float requestedSize;
	QString group;

	static SplitterWidgetSizing relativeSize(float relativeSize = 1, const QString& group = QString());
	static SplitterWidgetSizing pointSize(int size);

	QVariantMap serialize() const;
	static std::optional<SplitterWidgetSizing> deserialize(const QVariantMap& value);
};

/*!
    \ingroup splitter
*/
struct BINARYNINJAUIAPI SplitterWidget
{
	QString key;
	QWidget* widget;
	bool visible;
	SplitterWidgetSizing sizing;
	int actualSize, minimumSize;
};

/*!
    \ingroup splitter
*/
class BINARYNINJAUIAPI Splitter: public QWidget
{
	Q_OBJECT

	struct SplitterDragInfo
	{
		size_t left, right;
		int offset;
	};

	struct GroupInfo
	{
		QString group;
		std::set<SplitterWidget*> widgets;
		SplitterWidgetSizing sizing;
		int actualSize, minimumSize;
	};

	Qt::Orientation m_orientation;
	int m_handleSize;

	std::vector<SplitterWidget> m_widgets;
	std::map<QString, SplitterWidgetSizing> m_sizing;
	std::map<QString, SplitterWidgetSizing> m_groupSizing;

	std::optional<size_t> m_handleHover;
	std::optional<SplitterDragInfo> m_handleDrag;

	bool m_updatingLayout = false;

public:
	Splitter(Qt::Orientation orientation);

	void addWidget(const QString& key, QWidget* widget, const SplitterWidgetSizing& defaultSize);
	void insertWidget(const QString& key, size_t index, QWidget* widget, const SplitterWidgetSizing& defaultSize);
	void addRelativeSizeGroup(const QString& group, float relativeSize);

	QVariantMap saveState();
	void saveState(QSettings& settings, const QString& stateName);
	void restoreState(const QVariantMap& state);
	void restoreState(const QSettings& settings, const QString& stateName);
	void resetToDefault();

	std::optional<SplitterWidgetSizing> sizing(const QString& key) const;
	std::optional<SplitterWidgetSizing> sizing(QWidget* widget) const;
	void setSizing(const QString& key, const SplitterWidgetSizing& sizing);
	void setRequestedSize(const QString& key, float size);
	void setRequestedSize(QWidget* widget, float size);

	Qt::Orientation orientation() const { return m_orientation; }
	void setOrientation(Qt::Orientation orientation);

	QList<int> sizes() const;
	void setSizes(const QList<int>& sizes);

protected:
	virtual void paintEvent(QPaintEvent* event) override;
	virtual void mousePressEvent(QMouseEvent* event) override;
	virtual void mouseMoveEvent(QMouseEvent* event) override;
	virtual void mouseReleaseEvent(QMouseEvent* event) override;
	virtual void leaveEvent(QEvent* event) override;
	virtual void resizeEvent(QResizeEvent* event) override;
	virtual void childEvent(QChildEvent* event) override;
	virtual bool event(QEvent* event) override;

private:
	void forAllSplitterHandles(const std::function<void(size_t leftIdx, size_t rightIdx, int pos)>& func);
	void processLayout(bool computeFromExisting,
		const std::function<int(int availablePointSize)>& processPointSizeWidgets,
		const std::function<void(int availableWidgetSize)>& processRelativeSizeWidgets);
	void getWidgetsForSizingStyle(SplitterWidgetSizingStyle style,
		std::set<SplitterWidget*>& widgets, std::vector<GroupInfo>& groups);
	void regenerateLayoutForRelativeSizedWidgets(
		std::set<SplitterWidget*> widgets, std::vector<GroupInfo> groups, int availableSize);
	void regenerateLayout();
	void calculateRequestedSizesForRelativeSizedWidgets(
		const std::set<SplitterWidget*>& widgets, const std::vector<GroupInfo>& groups, int availableSize);
	void calculateRequestedSizesForActualLayout();
	void updateWidgetPositions();

Q_SIGNALS:
	void splitterMoved();
};
