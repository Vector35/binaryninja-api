#include <cstring>
#include <algorithm>
#include <QtGui/QClipboard>
#include <QtGui/QGuiApplication>
#include <QtCore/QStringList>
#include <QtWidgets/QMenu>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QVBoxLayout>
#include <QtCore/QFile>
#include "resources.h"
#include "view.h"
#include "fontsettings.h"


static std::string GetResourceFileExtension(const std::string& type)
{
	if (type == "RT_ICON" || type == "RT_GROUP_ICON")
		return ".ico";
	if (type == "RT_CURSOR" || type == "RT_GROUP_CURSOR")
		return ".cur";
	if (type == "RT_BITMAP")
		return ".bmp";
	if (type == "RT_HTML")
		return ".html";
	if (type == "RT_MANIFEST")
		return ".xml";
	if (type == "RT_FONT")
		return ".fnt";
	if (type == "RT_VERSION" || type == "RT_STRING" || type == "RT_MESSAGETABLE"
		|| type == "RT_RCDATA" || type == "RT_DLGINCLUDE")
		return ".bin";
	return ".bin";
}


ResourcesModel::ResourcesModel(QWidget* parent, BinaryViewRef data) : QAbstractItemModel(parent)
{
	m_data = data;
	m_sortCol = TypeCol;
	m_sortOrder = Qt::AscendingOrder;

	auto md = m_data->QueryMetadata("PEResources");
	if (md && md->IsArray())
	{
		for (auto& item : md->GetArray())
		{
			if (!item->IsKeyValueStore())
				continue;
			auto kv = item->GetKeyValueStore();

			ResourceEntry entry;
			auto getStr = [&](const std::string& key) -> std::string {
				auto it = kv.find(key);
				if (it != kv.end() && it->second->IsString())
					return it->second->GetString();
				return "";
			};
			auto getUint = [&](const std::string& key) -> uint64_t {
				auto it = kv.find(key);
				if (it != kv.end() && it->second->IsUnsignedInteger())
					return it->second->GetUnsignedInteger();
				return 0;
			};

			entry.type = getStr("type");
			entry.typeId = getUint("typeId");
			entry.name = getStr("name");
			entry.nameId = getUint("nameId");
			entry.language = getStr("language");
			entry.languageId = getUint("languageId");
			entry.dataRva = getUint("dataRva");
			entry.dataSize = getUint("dataSize");
			entry.dataAddress = getUint("dataAddress");
			entry.codepage = getUint("codepage");
			entry.preview = getStr("preview");

			m_allEntries.push_back(entry);
		}
	}
	m_entries = m_allEntries;
}


int ResourcesModel::columnCount(const QModelIndex&) const
{
	return ColumnCount;
}


int ResourcesModel::rowCount(const QModelIndex& parent) const
{
	if (parent.isValid())
		return 0;
	return (int)m_entries.size();
}


QVariant ResourcesModel::data(const QModelIndex& index, int role) const
{
	if (!index.isValid() || index.row() >= (int)m_entries.size())
		return QVariant();

	const auto& entry = m_entries[index.row()];

	switch (role)
	{
	case Qt::DisplayRole:
		switch (index.column())
		{
		case TypeCol:
			return QString::fromStdString(entry.type);
		case NameCol:
			return QString::fromStdString(entry.name);
		case LanguageCol:
			return QString::fromStdString(entry.language);
		case SizeCol:
			return QString("0x") + QString::number(entry.dataSize, 16);
		case AddressCol:
			return QString("0x") + QString::number(entry.dataAddress, 16);
		case PreviewCol:
			return QString::fromStdString(entry.preview);
		}
		break;
	case Qt::ForegroundRole:
		if (index.column() == AddressCol)
			return getThemeColor(AddressColor);
		break;
	default:
		break;
	}

	return QVariant();
}


QVariant ResourcesModel::headerData(int section, Qt::Orientation orientation, int role) const
{
	if (orientation == Qt::Vertical || role != Qt::DisplayRole)
		return QVariant();

	switch (section)
	{
	case TypeCol:     return QString("Type");
	case NameCol:     return QString("Name");
	case LanguageCol: return QString("Language");
	case SizeCol:     return QString("Size");
	case AddressCol:  return QString("Address");
	case PreviewCol:  return QString("Preview");
	}
	return QVariant();
}


QModelIndex ResourcesModel::index(int row, int col, const QModelIndex& parent) const
{
	if (parent.isValid())
		return QModelIndex();
	if (row >= (int)m_entries.size() || col >= ColumnCount)
		return QModelIndex();
	return createIndex(row, col);
}


QModelIndex ResourcesModel::parent(const QModelIndex&) const
{
	return QModelIndex();
}


const ResourceEntry* ResourcesModel::getEntry(const QModelIndex& index) const
{
	if (!index.isValid() || index.row() >= (int)m_entries.size())
		return nullptr;
	return &m_entries[index.row()];
}


void ResourcesModel::performSort(int col, Qt::SortOrder order)
{
	std::sort(m_entries.begin(), m_entries.end(), [&](const ResourceEntry& a, const ResourceEntry& b) {
		bool less = false;
		bool greater = false;
		switch (col)
		{
		case TypeCol:
			less = a.type < b.type;
			greater = a.type > b.type;
			break;
		case NameCol:
			// Sort numerically by ID when both names are numeric (e.g. "#303")
			less = a.nameId < b.nameId;
			greater = a.nameId > b.nameId;
			if (a.nameId == b.nameId)
			{
				less = a.name < b.name;
				greater = a.name > b.name;
			}
			break;
		case LanguageCol:
			less = a.language < b.language;
			greater = a.language > b.language;
			break;
		case SizeCol:
			less = a.dataSize < b.dataSize;
			greater = a.dataSize > b.dataSize;
			break;
		case AddressCol:
			less = a.dataAddress < b.dataAddress;
			greater = a.dataAddress > b.dataAddress;
			break;
		case PreviewCol:
			less = a.preview < b.preview;
			greater = a.preview > b.preview;
			break;
		}
		if (order == Qt::AscendingOrder)
			return less;
		return greater;
	});
}


void ResourcesModel::sort(int col, Qt::SortOrder order)
{
	beginResetModel();
	m_sortCol = col;
	m_sortOrder = order;
	performSort(col, order);
	endResetModel();
}


void ResourcesModel::setFilter(const std::string& filterText, FilterOptions options)
{
	beginResetModel();
	m_entries.clear();
	bool caseSensitive = options.testFlag(FilterOption::CaseSensitiveOption);
	for (auto& entry : m_allEntries)
	{
		if (FilteredView::match(entry.type, filterText, caseSensitive))
			m_entries.push_back(entry);
		else if (FilteredView::match(entry.name, filterText, caseSensitive))
			m_entries.push_back(entry);
		else if (FilteredView::match(entry.language, filterText, caseSensitive))
			m_entries.push_back(entry);
		else if (FilteredView::match(entry.preview, filterText, caseSensitive))
			m_entries.push_back(entry);
	}
	performSort(m_sortCol, m_sortOrder);
	endResetModel();
}


ResourcesTreeView::ResourcesTreeView(ResourcesWidget* parent, TriageView* view, BinaryViewRef data) : QTreeView(parent)
{
	setFont(getMonospaceFont(this));

	m_data = data;
	m_parent = parent;
	m_view = view;

	// Allow view-specific shortcuts when resources are focused
	m_actionHandler.setupActionHandler(this);
	m_actionHandler.setActionContext([=, this]() { return m_view->actionContext(); });

	m_model = new ResourcesModel(this, m_data);
	setModel(m_model);
	setRootIsDecorated(false);
	setUniformRowHeights(true);
	setSortingEnabled(true);
	setSelectionMode(QAbstractItemView::ExtendedSelection);
	setSelectionBehavior(QAbstractItemView::SelectRows);
	setAllColumnsShowFocus(true);
	sortByColumn(ResourcesModel::TypeCol, Qt::AscendingOrder);
	for (int i = 0; i < ResourcesModel::ColumnCount; i++)
		resizeColumnToContents(i);

	setContextMenuPolicy(Qt::CustomContextMenu);
	connect(this, &QTreeView::customContextMenuRequested, this, [this](const QPoint& pos) {
		const ResourceEntry* entry = m_model->getEntry(indexAt(pos));
		if (!entry)
			return;
		QMenu menu(this);
		menu.addAction("Save Resource to File...", this, &ResourcesTreeView::saveSelectedResource);
		menu.addAction("Save All Resources to Folder...", this, &ResourcesTreeView::saveAllResources);
		menu.addSeparator();
		menu.addAction("Copy", this, &ResourcesTreeView::copySelection);
		menu.exec(viewport()->mapToGlobal(pos));
	});

	connect(selectionModel(), &QItemSelectionModel::currentChanged, this, &ResourcesTreeView::resourceSelected);
	connect(this, &QTreeView::doubleClicked, this, &ResourcesTreeView::resourceDoubleClicked);

	m_actionHandler.bindAction("Copy", UIAction([this]() { copySelection(); }, [this]() { return canCopySelection(); }));
}


void ResourcesTreeView::copySelection()
{
	if (!model() || !selectionModel())
		return;

	QModelIndexList rows = selectionModel()->selectedRows();
	if (rows.isEmpty())
		return;

	std::sort(rows.begin(), rows.end(), [](const QModelIndex& a, const QModelIndex& b) { return a.row() < b.row(); });

	QStringList lines;
	for (const QModelIndex& rowIndex : rows)
	{
		QStringList cells;
		for (int column = 0; column < m_model->columnCount(QModelIndex()); column++)
		{
			if (isColumnHidden(column))
				continue;

			QModelIndex idx = m_model->index(rowIndex.row(), column, QModelIndex());
			cells << m_model->data(idx, Qt::DisplayRole).toString();
		}
		lines << cells.join("\t");
	}

	if (QClipboard* clipboard = QGuiApplication::clipboard())
		clipboard->setText(lines.join("\n"));
}


bool ResourcesTreeView::canCopySelection() const
{
	return !selectionModel()->selectedRows().isEmpty();
}


static std::string SanitizeFilename(std::string name)
{
	for (char& c : name)
	{
		if (c == '#' || c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
			c = '_';
	}
	return name;
}


void ResourcesTreeView::saveSelectedResource()
{
	QModelIndexList rows = selectionModel()->selectedRows();
	if (rows.isEmpty())
		return;

	const ResourceEntry* entry = m_model->getEntry(rows.first());
	if (!entry || entry->dataSize == 0)
		return;

	// Suggest a filename
	std::string ext = GetResourceFileExtension(entry->type);
	std::string suggestedName = SanitizeFilename(entry->type);
	if (!entry->name.empty())
		suggestedName += "_" + SanitizeFilename(entry->name);
	if (!entry->language.empty())
		suggestedName += "_" + SanitizeFilename(entry->language);
	suggestedName += ext;

	QString path = QFileDialog::getSaveFileName(this, "Save Resource", QString::fromStdString(suggestedName));
	if (path.isEmpty())
		return;

	BinaryNinja::DataBuffer buf = m_data->ReadBuffer(entry->dataAddress, entry->dataSize);
	QFile file(path);
	if (file.open(QIODevice::WriteOnly))
	{
		file.write(reinterpret_cast<const char*>(buf.GetData()), buf.GetLength());
		file.close();
	}
}


void ResourcesTreeView::saveAllResources()
{
	QString dir = QFileDialog::getExistingDirectory(this, "Save All Resources to Folder");
	if (dir.isEmpty())
		return;

	const auto& entries = m_model->getAllEntries();
	for (const auto& entry : entries)
	{
		if (entry.dataSize == 0)
			continue;

		// Build filename: type/name_language.ext, organized into type subdirectories
		std::string subdir = SanitizeFilename(entry.type.empty() ? "unknown" : entry.type);
		QDir typeDir(dir + "/" + QString::fromStdString(subdir));
		if (!typeDir.exists())
			typeDir.mkpath(".");

		std::string basename = entry.name.empty() ? "unnamed" : SanitizeFilename(entry.name);
		if (!entry.language.empty())
			basename += "_" + SanitizeFilename(entry.language);
		basename += GetResourceFileExtension(entry.type);

		QString path = typeDir.filePath(QString::fromStdString(basename));

		BinaryNinja::DataBuffer buf = m_data->ReadBuffer(entry.dataAddress, entry.dataSize);
		QFile file(path);
		if (file.open(QIODevice::WriteOnly))
		{
			file.write(reinterpret_cast<const char*>(buf.GetData()), buf.GetLength());
			file.close();
		}
	}
}


void ResourcesTreeView::resourceSelected(const QModelIndex& cur, const QModelIndex&)
{
	const ResourceEntry* entry = m_model->getEntry(cur);
	if (entry)
		m_view->setCurrentOffset(entry->dataAddress);
}


void ResourcesTreeView::resourceDoubleClicked(const QModelIndex& cur)
{
	const ResourceEntry* entry = m_model->getEntry(cur);
	if (entry)
	{
		ViewFrame* viewFrame = ViewFrame::viewFrameForWidget(this);
		if (viewFrame)
		{
			viewFrame->navigate("Linear:" + viewFrame->getCurrentDataType(), entry->dataAddress);
		}
	}
}


void ResourcesTreeView::setFilter(const std::string& filterText, FilterOptions options)
{
	m_model->setFilter(filterText, options);
}


void ResourcesTreeView::scrollToFirstItem()
{
	scrollToTop();
}


void ResourcesTreeView::scrollToCurrentItem()
{
	scrollTo(currentIndex());
}


void ResourcesTreeView::ensureSelection()
{
	if (auto current = currentIndex(); !current.isValid())
		setCurrentIndex(m_model->index(0, 0, QModelIndex()));
}


void ResourcesTreeView::activateSelection()
{
	ensureSelection();
	if (auto current = currentIndex(); current.isValid())
		resourceDoubleClicked(current);
}


void ResourcesTreeView::closeFilter()
{
	setFocus(Qt::OtherFocusReason);
}


void ResourcesTreeView::keyPressEvent(QKeyEvent* event)
{
	if ((event->text().size() == 1) && (event->text()[0] > ' ') && (event->text()[0] <= '~'))
	{
		m_parent->showFilter(event->text());
		event->accept();
	}
	else if ((event->key() == Qt::Key_Return) || (event->key() == Qt::Key_Enter))
	{
		QList<QModelIndex> sel = selectionModel()->selectedIndexes();
		if (sel.size() != 0)
			resourceDoubleClicked(sel[0]);
	}
	else if (event->matches(QKeySequence::Copy))
	{
		copySelection();
		event->accept();
		return;
	}
	QTreeView::keyPressEvent(event);
}


ResourcesWidget::ResourcesWidget(QWidget* parent, TriageView* view, BinaryViewRef data) : QWidget(parent)
{
	QVBoxLayout* layout = new QVBoxLayout();
	layout->setContentsMargins(0, 0, 0, 0);
	ResourcesTreeView* resources = new ResourcesTreeView(this, view, data);
	m_filter = new FilteredView(this, resources, resources);
	m_filter->setFilterPlaceholderText("Search resources");
	layout->addWidget(m_filter, 1);
	setLayout(layout);
	setMinimumSize(UIContext::getScaledWindowSize(100, 196));
}


void ResourcesWidget::showFilter(const QString& filter)
{
	m_filter->showFilter(filter);
}
