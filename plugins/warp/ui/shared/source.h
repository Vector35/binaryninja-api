#pragma once

#include <QWidget>
#include <QDesktopServices>
#include <QInputDialog>
#include <QListWidget>
#include <QTableView>

#include "theme.h"
#include "warp.h"

class WarpSourcesModel final : public QAbstractTableModel
{
	Q_OBJECT

public:
	enum Columns : int
	{
		GuidCol = 0,
		PathCol,
		WritableCol,
		UncommittedCol,
		ColumnCount
	};

	explicit WarpSourcesModel(QObject* parent = nullptr) : QAbstractTableModel(parent) {}

	void setContainer(Warp::Ref<Warp::Container> container)
	{
		m_container = std::move(container);
		reload();
	}

	void reload()
	{
		// Fetch synchronously (can be adapted to async if needed)
		beginResetModel();
		m_rows.clear();
		for (const auto& src : m_container->GetSources())
		{
			QString guid = QString::fromStdString(src.ToString());
			QString path = QString::fromStdString(m_container->SourcePath(src).value_or(std::string {}));
			bool writable = m_container->IsSourceWritable(src);
			bool uncommitted = m_container->IsSourceUncommitted(src);
			m_rows.push_back({guid, path, writable, uncommitted});
		}
		endResetModel();
	}

	int rowCount(const QModelIndex& parent = QModelIndex()) const override
	{
		if (parent.isValid())
			return 0;
		return static_cast<int>(m_rows.size());
	}

	int columnCount(const QModelIndex& parent = QModelIndex()) const override
	{
		Q_UNUSED(parent);
		return ColumnCount;
	}

	QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;

	QVariant headerData(int section, Qt::Orientation orientation, int role) const override
	{
		if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
		{
			switch (section)
			{
			case GuidCol:
				return "Source GUID";
			case PathCol:
				return "Path";
			case WritableCol:
				return "Writable";
			case UncommittedCol:
				return "Uncommitted";
			default:
				return {};
			}
		}
		return {};
	}

private:
	struct Row
	{
		QString guid;
		QString path;
		bool writable;
		bool uncommitted;
	};

	std::vector<Row> m_rows;
	Warp::Ref<Warp::Container> m_container;
};


class WarpSourcesView : public QTableView
{
	Q_OBJECT

public:
	explicit WarpSourcesView(QWidget* parent = nullptr);

	void setContainer(Warp::Ref<Warp::Container> container);
	bool addSource();

	[[nodiscard]] WarpSourcesModel* sourceModel() const { return m_model; }
	[[nodiscard]] std::optional<Warp::Source> sourceFromRow(int row) const;

private:
	WarpSourcesModel* m_model = nullptr;
	Warp::Ref<Warp::Container> m_container;
};