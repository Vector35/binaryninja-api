#include "source.h"

#include <QClipboard>
#include <QFileInfo>
#include <QHeaderView>
#include <QPainter>

QVariant WarpSourcesModel::data(const QModelIndex& index, int role) const
{
	if (!index.isValid())
		return {};
	if (index.row() < 0 || index.row() >= rowCount())
		return {};

	const auto& r = m_rows[static_cast<size_t>(index.row())];

	// Build a small two-dot status icon (left: writable, right: uncommitted)
	auto statusIcon = [](bool writable, bool uncommitted) -> QIcon {
		static QIcon cache[2][2];  // [writable][uncommitted]
		QIcon& cached = cache[writable ? 1 : 0][uncommitted ? 1 : 0];
		if (!cached.isNull())
			return cached;

		const int w = 16, h = 12, radius = 4;
		QPixmap pm(w, h);
		pm.fill(Qt::transparent);
		QPainter p(&pm);
		p.setRenderHint(QPainter::Antialiasing, true);

		// Colors
		QColor writableOn(76, 175, 80);        // green
		QColor writableOff(158, 158, 158);     // grey
		QColor uncommittedOn(255, 193, 7);     // amber
		QColor uncommittedOff(158, 158, 158);  // grey

		// Left dot: writable
		p.setBrush(writable ? writableOn : writableOff);
		p.setPen(Qt::NoPen);
		p.drawEllipse(QPoint(4, h / 2), radius, radius);

		// Right dot: uncommitted
		p.setBrush(uncommitted ? uncommittedOn : uncommittedOff);
		p.drawEllipse(QPoint(w - 6, h / 2), radius, radius);

		p.end();
		cached = QIcon(pm);
		return cached;
	};

	if (role == Qt::DecorationRole && index.column() == PathCol)
	{
		return statusIcon(r.writable, r.uncommitted);
	}

	if (role == Qt::ToolTipRole && index.column() == PathCol)
	{
		QStringList parts;
		parts << (r.writable ? "Writable" : "Read-only");
		parts << (r.uncommitted ? "Uncommitted changes" : "No uncommitted changes");
		return parts.join(" • ");
	}

	if (role == Qt::DisplayRole)
	{
		switch (index.column())
		{
		case GuidCol:
			return r.guid;
		case PathCol:
			return r.path;
		case WritableCol:
			return r.writable ? "Yes" : "No";
		case UncommittedCol:
			return r.uncommitted ? "Yes" : "No";
		default:
			return {};
		}
	}

	if (role == Qt::CheckStateRole)
	{
		// Optional: expose as checkboxes if someone ever shows these columns
		switch (index.column())
		{
		case WritableCol:
			return r.writable ? Qt::Checked : Qt::Unchecked;
		case UncommittedCol:
			return r.uncommitted ? Qt::Checked : Qt::Unchecked;
		default:
			break;
		}
	}

	return {};
}

WarpSourcesView::WarpSourcesView(QWidget* parent) : QTableView(parent)
{
	m_model = new WarpSourcesModel(this);
	QTableView::setModel(m_model);

	horizontalHeader()->setStretchLastSection(true);
	setSelectionBehavior(SelectRows);
	setSelectionMode(SingleSelection);

	// Make the table look like a simple list that shows only the source path
	setShowGrid(false);
	verticalHeader()->setVisible(false);
	horizontalHeader()->setVisible(false);
	setAlternatingRowColors(false);
	setEditTriggers(NoEditTriggers);
	setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
	setWordWrap(false);
	setIconSize(QSize(16, 12));
	// Ensure long paths truncate from the left: "...tail/of/the/path"
	setTextElideMode(Qt::ElideLeft);

	// Hide GUID column, keep only the Path column visible
	setColumnHidden(WarpSourcesModel::GuidCol, true);
	// Also hide boolean columns; their state is shown as an icon next to the path
	setColumnHidden(WarpSourcesModel::WritableCol, true);
	setColumnHidden(WarpSourcesModel::UncommittedCol, true);
	// Ensure the remaining (Path) column fills the width
	horizontalHeader()->setSectionResizeMode(WarpSourcesModel::PathCol, QHeaderView::Stretch);

	// Per-item context menu
	setContextMenuPolicy(Qt::CustomContextMenu);
	connect(this, &QWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
		if (!m_model || !m_container)
			return;

		QMenu menu(this);
		const QModelIndex index = indexAt(pos);

		if (!index.isValid())
		{
			QAction* actAdd = menu.addAction(tr("Add Source"));
			QAction* chosen = menu.exec(viewport()->mapToGlobal(pos));
			if (!chosen)
				return;
			if (chosen == actAdd)
				addSource();
		}
		else
		{
			setCurrentIndex(index.sibling(index.row(), WarpSourcesModel::PathCol));

			const int row = index.row();
			const QModelIndex pathIdx = m_model->index(row, WarpSourcesModel::PathCol);
			const QModelIndex guidIdx = m_model->index(row, WarpSourcesModel::GuidCol);
			const QString path = m_model->data(pathIdx, Qt::DisplayRole).toString();
			const QFileInfo fi(path);

			const QString guid = m_model->data(guidIdx, Qt::DisplayRole).toString();

			QAction* actReveal = menu.addAction(tr("Reveal in File Browser"));
			actReveal->setEnabled(fi.exists());
			QAction* actCopyPath = menu.addAction(tr("Copy Path"));
			QAction* actCopyGuid = menu.addAction(tr("Copy GUID"));

			QAction* chosen = menu.exec(viewport()->mapToGlobal(pos));
			if (!chosen)
				return;
			if (chosen == actCopyPath)
				QGuiApplication::clipboard()->setText(path);
			else if (chosen == actCopyGuid)
				QGuiApplication::clipboard()->setText(guid);
			else if (chosen == actReveal)
				QDesktopServices::openUrl(QUrl::fromLocalFile(fi.absoluteFilePath()));
		}
	});
}

void WarpSourcesView::setContainer(Warp::Ref<Warp::Container> container)
{
	m_container = std::move(container);
	m_model->setContainer(m_container);
}

bool WarpSourcesView::addSource()
{
	if (!m_model || !m_container)
		return false;

	std::string sourceName;
	if (!BinaryNinja::GetTextLineInput(sourceName, "Source name:", "Add Source"))
		return false;
	if (const auto sourceId = m_container->AddSource(sourceName); !sourceId.has_value())
	{
		BinaryNinja::LogAlertF("Failed to add source: {}", sourceName);
		return false;
	}
	m_model->reload();
	return true;
}

std::optional<Warp::Source> WarpSourcesView::sourceFromRow(int row) const
{
	if (!m_model || row < 0 || row >= m_model->rowCount())
		return std::nullopt;
	const QModelIndex guidIdx = m_model->index(row, WarpSourcesModel::GuidCol);
	std::string guidStr = m_model->data(guidIdx, Qt::DisplayRole).toString().toStdString();
	return Warp::WarpUUID::FromString(guidStr);
}