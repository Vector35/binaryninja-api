#pragma once

#include <QtWidgets/QWidget>
#include "theme.h"
#include "viewframe.h"
#include "tabwidget.h"

class BINARYNINJAUIAPI GlobalAreaWidget : public QWidget
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

	virtual void notifyFontChanged() {}
	virtual void notifyOffsetChanged(uint64_t /*offset*/) {}
	virtual void notifyThemeChanged() {}
	virtual void notifyViewChanged(ViewFrame* /*frame*/) {}
	virtual void notifyViewLocationChanged(View* /*view*/, const ViewLocation& /*viewLocation*/) {}
	virtual void focus();
};

class BINARYNINJAUIAPI GlobalAreaTabStyle : public DockableTabStyle
{
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
	virtual DockableTabStyle* duplicate() override;
};

class BINARYNINJAUIAPI CloseButton : public QWidget
{
	Q_OBJECT

	bool m_mouseInside = false;
	bool m_buttonDown = false;
	QTimer* m_timer;

  public:
	CloseButton();
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

class BINARYNINJAUIAPI GlobalArea : public QWidget
{
	Q_OBJECT

	SplitTabWidget* m_tabs;
	DockableTabCollection* m_collection;
	QSplitter* m_parentSplitter = nullptr;
	std::optional<QList<int>> m_pendingParentSplitterSizes, m_savedParentSplitterSizes;

	static std::vector<std::function<GlobalAreaWidget*(UIContext*)>> m_widgetFactories;

	QString actionNameForWidget(const QString& title);
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
	GlobalAreaWidget* widget(const QString& title);
	void closeTab(QWidget* widget);

	void saveSizes(const QSettings& settings, const QString& windowStateName);
	void saveState(const QSettings& settings, const QString& windowStateName);
	void restoreSizes(const QSettings& settings, const QString& windowStateName);
	void restoreState(const QSettings& settings, const QString& windowStateName);

	static GlobalArea* current()
	{
		UIContext* context = UIContext::activeContext();
		if (!context)
			return nullptr;
		return context->globalArea();
	}

	template <class T>
	static T* widget(const QString& title)
	{
		GlobalArea* globalArea = current();
		if (!globalArea)
			return (T*)nullptr;
		GlobalAreaWidget* widget = globalArea->widget(title);
		if (!widget)
			return (T*)nullptr;
		return qobject_cast<T*>(widget);
	}

	template <class T>
	static UIAction globalAreaAction(const QString& title, const std::function<void(T* obj)>& activate)
	{
		return globalAreaAction<T>(
		    title, [=](T* obj, const UIActionContext&) { activate(obj); },
		    [=](T*, const UIActionContext&) { return true; });
	}

	template <class T>
	static UIAction globalAreaAction(
	    const QString& title, const std::function<void(T* obj, const UIActionContext& ctxt)>& activate)
	{
		return globalAreaAction<T>(title, activate, [](T*, const UIActionContext&) { return true; });
	}

	template <class T>
	static UIAction globalAreaAction(
	    const QString& title, const std::function<void(T* obj)>& activate, const std::function<bool(T* obj)>& isValid)
	{
		return globalAreaAction<T>(
		    title, [=](T* obj, const UIActionContext&) { activate(obj); },
		    [=](T* obj, const UIActionContext&) { return isValid(obj); });
	}

	template <class T>
	static UIAction globalAreaAction(const QString& title,
	    const std::function<void(T* obj, const UIActionContext& ctxt)>& activate,
	    const std::function<bool(T* obj, const UIActionContext& ctxt)>& isValid)
	{
		std::function<T*(const UIActionContext& ctxt)> lookup = [=](const UIActionContext& ctxt) {
			if (!ctxt.context)
				return (T*)nullptr;
			GlobalArea* globalArea = ctxt.context->globalArea();
			if (!globalArea || !globalArea->isWidgetVisible(title))
				return (T*)nullptr;
			GlobalAreaWidget* widget = globalArea->widget(title);
			if (!widget)
				return (T*)nullptr;
			return qobject_cast<T*>(widget);
		};
		return UIAction(
		    [=](const UIActionContext& ctxt) {
			    T* obj = lookup(ctxt);
			    if (obj)
				    activate(obj, ctxt);
		    },
		    [=](const UIActionContext& ctxt) {
			    T* obj = lookup(ctxt);
			    if (obj)
				    return isValid(obj, ctxt);
			    return false;
		    });
	}

	template <class T>
	static std::function<bool(const UIActionContext&)> globalAreaActionChecked(
	    const QString& title, const std::function<bool(T* obj)>& isChecked)
	{
		return globalAreaActionChecked<T>(title, [=](T* obj, const UIActionContext&) { return isChecked(obj); });
	}

	template <class T>
	static std::function<bool(const UIActionContext&)> globalAreaActionChecked(
	    const QString& title, const std::function<bool(T* obj, const UIActionContext& ctxt)>& isChecked)
	{
		return [=](const UIActionContext& ctxt) {
			if (!ctxt.context)
				return false;
			GlobalArea* globalArea = ctxt.context->globalArea();
			if (!globalArea || !globalArea->isWidgetVisible(title))
				return false;
			GlobalAreaWidget* widget = globalArea->widget(title);
			if (!widget)
				return false;
			T* obj = qobject_cast<T*>(widget);
			if (obj)
				return isChecked(obj, ctxt);
			return false;
		};
	}

  Q_SIGNALS:
	void widgetClosed(GlobalAreaWidget* widget);

  private Q_SLOTS:
	void currentChanged(QWidget* widget);
	void tabClosed(QWidget* widget);
	void hideButtonClicked();
};
