#pragma once

#include <QtWidgets/QWidget>
#include "theme.h"
#include "viewframe.h"
#include "tabwidget.h"

class BINARYNINJAUIAPI GlobalAreaWidget: public QWidget
{
	Q_OBJECT

protected:
	QString m_title;
	UIActionHandler m_actionHandler;
	ContextMenuManager* m_contextMenuManager = nullptr;
	Menu* m_menu = nullptr;

public:
	GlobalAreaWidget(const QString& title);

	const QString& title() const { return m_title; }

	virtual void notifyFontChanged() { }
	virtual void notifyOffsetChanged(uint64_t /*offset*/) { }
	virtual void notifyThemeChanged() { }
	virtual void notifyViewChanged(ViewFrame* /*frame*/) { }
	virtual void notifyViewLocationChanged(View* /*view*/, const ViewLocation& /*viewLocation*/) { }
	virtual void focus();
};

class BINARYNINJAUIAPI GlobalAreaTabStyle: public DockableTabStyle
{
	int closeButtonSize(const QWidget* widget) const;

public:
	virtual QSize sizeForTab(const QWidget* widget, const DockableTabInfo& info, int idx,
		int count, int active) const override;
	virtual QRect closeButtonRect(const QWidget* widget, const DockableTabInfo& info, int idx,
		int count, int active) const override;
	virtual QRect closeIconRect(const QWidget* widget, const DockableTabInfo& info, int idx,
		int count, int active) const override;
	virtual void paintTab(const QWidget* widget, QStylePainter& p, const DockableTabInfo& info, int idx,
		int count, int active, DockableTabInteractionState state, const QRect& rect) const override;
	virtual DockableTabStyle* duplicate() override;
};

class BINARYNINJAUIAPI GlobalAreaHideButton: public QWidget
{
	Q_OBJECT

	bool m_mouseInside = false;
	bool m_buttonDown = false;
	QTimer* m_timer;

public:
	GlobalAreaHideButton();
	virtual QSize sizeHint() const override;

protected:
	virtual void paintEvent(QPaintEvent* event) override;
	virtual void enterEvent(QEnterEvent* event) override;
	virtual void leaveEvent(QEvent* event) override;
	virtual void mouseMoveEvent(QMouseEvent* event) override;
	virtual void mousePressEvent(QMouseEvent* event) override;
	virtual void mouseReleaseEvent(QMouseEvent* event) override;

private Q_SLOTS:
	void underMouseTimerEvent();

Q_SIGNALS:
	void clicked();
};

class BINARYNINJAUIAPI GlobalArea: public QWidget
{
	Q_OBJECT

	SplitTabWidget* m_tabs;
	DockableTabCollection* m_collection;
	QSplitter* m_parentSplitter = nullptr;
	std::optional<QList<int>> m_pendingParentSplitterSizes, m_savedParentSplitterSizes;

	static std::vector<std::function<GlobalAreaWidget*(UIContext*)>> m_widgetFactories;

	QString actionNameForWidget(const QString &title);
	static QVariant sizesToVariant(const QList<int>& sizes);
	static std::optional<QList<int>> variantToSizes(const QVariant& variant);

public:
	GlobalArea();
	void setSplitter(QSplitter* splitter);

	void addWidget(GlobalAreaWidget* widget, bool canClose = false);
	static void addWidget(const std::function<GlobalAreaWidget*(UIContext*)>& createWidget);

	void initRegisteredWidgets(UIContext* context);

	void updateFonts();
	void updateTheme();
	void updateViewLocation(View* view, const ViewLocation& viewLocation);
	void viewChanged(ViewFrame* frame);

	bool isWidgetVisible(const QString& title);

	bool toggleVisible();
	bool toggleWidgetVisible(const QString& title);
	void focusWidget(const QString& title);

	void saveSizes(const QSettings& settings, const QString& windowStateName);
	void saveState(const QSettings& settings, const QString& windowStateName);
	void restoreSizes(const QSettings& settings, const QString& windowStateName);
	void restoreState(const QSettings& settings, const QString& windowStateName);

Q_SIGNALS:
	void widgetClosed(GlobalAreaWidget* widget);

private Q_SLOTS:
	void currentChanged(QWidget* widget);
	void tabClosed(QWidget* widget);
	void hideButtonClicked();
};
