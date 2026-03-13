#pragma once

#include <QDesktopServices>
#include <QInputDialog>
#include <QListWidget>
#include "shared/search.h"

#include "theme.h"
#include "warp.h"
#include "../../../../ui/mainwindow.h"
#include "shared/source.h"

class WarpContainerWidget : public QWidget
{
	Q_OBJECT

public:
	explicit WarpContainerWidget(Warp::Ref<Warp::Container> container, QWidget* parent = nullptr);

private:
	Warp::Ref<Warp::Container> m_container;

	QTabWidget* m_tabs = nullptr;

	// Sources
	WarpSourcesView* m_sourcesView = nullptr;
	QWidget* m_sourcesPage = nullptr;
	QTimer* m_refreshTimer = nullptr;

	// Search
	WarpSearchWidget* m_searchTab = nullptr;
};

class WarpContainersPane : public QWidget
{
	Q_OBJECT

public:
	explicit WarpContainersPane(QWidget* parent = nullptr);

	void refresh()
	{
		// Clear and repopulate from current container list
		m_list->clear();
		while (m_stack->count() > 0)
		{
			QWidget* w = m_stack->widget(0);
			m_stack->removeWidget(w);
			delete w;
		}
		m_containers.clear();
		populate();
		if (m_list->count() > 0)
			m_list->setCurrentRow(0);
	}

private:
	void populate()
	{
		// Retrieve all available containers
		const auto all = Warp::Container::All();
		m_containers = all;

		for (const auto& c : m_containers)
		{
			const QString name = QString::fromStdString(c->GetName());
			auto* item = new QListWidgetItem(name, m_list);
			item->setSizeHint(QSize(item->sizeHint().width(), itemHeightPx()));
			auto* widget = new WarpContainerWidget(c, m_stack);
			m_stack->addWidget(widget);
		}
	}

	static int itemHeightPx()
	{
		// A reasonable, readable height per entry
		return 28;
	}

private:
	QListWidget* m_list = nullptr;
	QStackedWidget* m_stack = nullptr;
	std::vector<Warp::Ref<Warp::Container>> m_containers;
};
