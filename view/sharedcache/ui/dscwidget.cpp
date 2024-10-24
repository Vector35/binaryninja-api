//
// by kat // 9/15/22.
//

// CURRENTLY UNUSED CODE

#include "dscwidget.h"

#include "ui/viewframe.h"
#include "ui/progresstask.h"

#include <QtCore/QMimeData>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QVBoxLayout>
#include <filesystem>
#include <QtWidgets>

namespace fs = std::filesystem;


/// Format an address as hexadecimal. Does not include leading '0x' prefix.
QString formatAddress(uint64_t address)
{
	return QString::number(address, 16).rightJustified(8, '0');
};

//===-- DSCContentsModelItem ------------------------------------------------===//

DSCContentsModelItem::DSCContentsModelItem(DSCContentsModelItem* parent) : DSCContentsModelItem(nullptr, {}, {}, parent)
{}

DSCContentsModelItem::DSCContentsModelItem(
	BinaryViewRef view, std::string name, std::string installName, DSCContentsModelItem* parent) :
	m_bv(view),
	m_name(name), m_installName(installName), m_parent(parent)
{
	if (!installName.empty())
		m_type = ImageModelItem;
	else
		m_type = FolderModelItem;
}

QString DSCContentsModelItem::displayName() const
{
	return QString::fromStdString(m_name);
}

size_t DSCContentsModelItem::childCount() const
{
	return m_children.size();
}

DSCContentsModelItem* DSCContentsModelItem::child(size_t index)
{
	if (index < 0 || index >= m_children.size())
		return nullptr;

	return m_children[index];
}

void DSCContentsModelItem::addChild(DSCContentsModelItem* item)
{
	item->m_parent = this;
	m_children.push_back(item);
}

DSCContentsModelItem* DSCContentsModelItem::parent() const
{
	return m_parent;
}

size_t DSCContentsModelItem::row() const
{
	if (!m_parent)
		return 0;
	auto it = std::find(m_parent->m_children.begin(), m_parent->m_children.end(), this);
	return it - m_parent->m_children.begin();
}

QVariant DSCContentsModelItem::data(int column) const
{
	switch (column)
	{
	case DSCContentsModel::NameColumn:
		return displayName();

	default:
		return QVariant();
	}
}

QImage DSCContentsModelItem::icon() const
{
	auto kind = data(DSCContentsModel::KindColumn).toString();
	auto icon = QImage(":/icons/images/ComponentTree_" + kind + ".png");

	return icon.scaled(16, 16, Qt::KeepAspectRatio);
}

//===-- DSCContentsModel ----------------------------------------------------===//

DSCContentsModel::DSCContentsModel(BinaryViewRef bv, QObject* parent) : QAbstractItemModel(parent), m_bv(bv)
{
	m_cache = new SharedCacheAPI::SharedCache(bv);
	refresh();
}

struct ItemNode
{
	ItemNode* parent = nullptr;
	std::string fullPath;
	std::string path;
	DSCContentsModelItem* assignedModelItem = nullptr;
	std::unordered_map<std::string, ItemNode*> edges {};
};

std::vector<std::string> split(std::string str, std::string token)
{
	std::vector<std::string> result;
	while (str.size())
	{
		int index = str.find(token);
		if (index != std::string::npos)
		{
			result.push_back(str.substr(0, index));
			str = str.substr(index + token.size());
			if (str.size() == 0)
				result.push_back(str);
		}
		else
		{
			result.push_back(str);
			str = "";
		}
	}
	return result;
}

void DSCContentsModel::refresh()
{
	std::scoped_lock<std::mutex> lock(m_updateMutex);

	// Using `{begin,end}ResetModel` here is not ideal and is a temporary
	// hack at best. Actual model indices should be updated. That requires
	// more work and will be implemented after more important things have
	// been taken care of.
	beginResetModel();

	auto inames = m_cache->GetAvailableImages();

	m_root = new DSCContentsModelItem();

	std::unordered_map<std::string, DSCContentsModelItem*> folders {};
	folders["/"] = m_root;
	for (const auto& iname : inames)
	{
		auto pathItems = split(iname, "/");
		pathItems.pop_back();  // skip filenames
		std::string fullPath = "/";

		for (const auto& item : pathItems)
		{
			if (item.empty())
				continue;
			auto parentPath = fullPath;
			fullPath += item + "/";
			if (folders.count(fullPath) == 0)
			{
				auto pnode = folders.at(parentPath);
				auto* nnode = new DSCContentsModelItem(m_bv, item, "", pnode);
				pnode->addChild(nnode);
				folders[fullPath] = nnode;
			}
		}
	}

	// Ok, all our folders are in place. Put files in them.

	for (const auto& iname : inames)
	{
		auto file = fs::path(iname).filename().string();
		auto folderName = fs::path(iname).parent_path().string() + "/";
		if (auto folder = folders.find(folderName); folder != folders.end())
		{
			auto* nnode = new DSCContentsModelItem(m_bv, file, iname, folder->second);
			folder->second->addChild(nnode);
		}
		else
			BNLogError("DSCView Sidebar Logic Error: Couldn't find folder for %s %s %s", iname.c_str(), file.c_str(),
				folderName.c_str());
	}

	endResetModel();
}

QModelIndex DSCContentsModel::index(int row, int column, const QModelIndex& parentIndex) const
{
	if (!hasIndex(row, column, parentIndex))
		return QModelIndex();

	// Use the parent index's item if it is valid, otherwise use the root.
	DSCContentsModelItem* parent = nullptr;
	if (parentIndex.isValid())
		parent = static_cast<DSCContentsModelItem*>(parentIndex.internalPointer());
	else
		parent = m_root;

	// If the child is found, create an index for it; use an invalid index otherwise.
	auto item = parent->child(row);
	if (item)
		return createIndex(row, column, item);

	return QModelIndex();
}

QModelIndex DSCContentsModel::parent(const QModelIndex& index) const
{
	if (!index.isValid())
		return QModelIndex();

	auto child = static_cast<DSCContentsModelItem*>(index.internalPointer());
	auto parent = child->parent();
	if (parent == m_root || parent == nullptr)
		return QModelIndex();

	return createIndex(parent->row(), 0, parent);
}

QVariant DSCContentsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
	if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
	{
		switch (section)
		{
		case DSCContentsModel::NameColumn:
			return "Name";
		default:
			return "";
		}
	}

	return QAbstractItemModel::headerData(section, orientation, role);
}

constexpr int ComponentGuidDataRole = 64;

QVariant DSCContentsModel::data(const QModelIndex& index, int role) const
{
	if (!index.isValid())
		return QVariant();

	auto item = static_cast<DSCContentsModelItem*>(index.internalPointer());
	if (!item)
		return {};

	switch (role)
	{
	case Qt::DisplayRole:
		return item->data(index.column());
	default:
		return {};
	}
}

bool DSCContentsModel::setData(const QModelIndex& index, const QVariant& value, int role)
{
	return false;
}

Qt::ItemFlags DSCContentsModel::flags(const QModelIndex& index) const
{
	if (!index.isValid())
		return Qt::ItemIsDropEnabled;  // Root node

	Qt::ItemFlags flags = QAbstractItemModel::flags(index);

	return flags;
}


int DSCContentsModel::rowCount(const QModelIndex& parent) const
{
	DSCContentsModelItem* item;
	if (!parent.isValid())
		item = m_root;
	else
		item = static_cast<DSCContentsModelItem*>(parent.internalPointer());

	return item->childCount();
}

int DSCContentsModel::columnCount(const QModelIndex& parent) const
{
	return 1;
}

Qt::DropActions DSCContentsModel::supportedDropActions() const
{
	return Qt::IgnoreAction;
}


//===-- ComponentFilterModel ----------------------------------------------===//

DSCFilterModel::DSCFilterModel(BinaryViewRef data, QObject* parent) :
	QSortFilterProxyModel(parent), m_model(new DSCContentsModel(data))
{
	setSourceModel(m_model);
}

bool DSCFilterModel::filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const
{
	auto index = sourceModel()->index(sourceRow, 0, sourceParent);
	if (!index.isValid())
		return false;

	return QSortFilterProxyModel::filterAcceptsRow(sourceRow, sourceParent);
}

DSCSidebarView::DSCSidebarView(ViewFrame* frame, BinaryViewRef data, QWidget* parent) :
	QTreeView(parent), m_data(data), m_frame(frame), m_parent(parent)
{
	connect(this, &DSCSidebarView::doubleClicked, this, &DSCSidebarView::navigateToIndex);

	setContextMenuPolicy(Qt::CustomContextMenu);
	connect(this, &DSCSidebarView::customContextMenuRequested, [this](const QPoint& p) {
		auto menu = createContextMenu();
		menu->popup(viewport()->mapToGlobal(p));
	});
}


void DSCSidebarView::navigateToIndex(const QModelIndex& index)
{
	auto filterParent = static_cast<DSCSidebarWidget*>(m_parent);
	if (!filterParent)
		return;
	auto modelItem = static_cast<DSCContentsModelItem*>(filterParent->m_model->mapToSource(index).internalPointer());

	if (modelItem->m_installName.empty())
		return;

	QMessageBox::StandardButton reply;
	reply = QMessageBox::question(this, "Load Image", "Load " + QString::fromStdString(modelItem->m_name) + "?",
		QMessageBox::Yes | QMessageBox::No);

	if (reply == QMessageBox::Yes)
	{
		SharedCacheAPI::SharedCache* cache = new SharedCacheAPI::SharedCache(m_data);
		cache->LoadImageWithInstallName(modelItem->m_installName);
		m_data->UpdateAnalysis();
	}
}

QMenu* DSCSidebarView::createContextMenu()
{
	auto menu = new QMenu();

	return menu;
}

//===-- ComponentTree -----------------------------------------------------===//

DSCSidebarWidget::DSCSidebarWidget(ViewFrame* frame, BinaryViewRef data) :
	SidebarWidget("dyld_shared_cache"), m_data(data), m_frame(frame), m_header(new QWidget)
{
	auto view = data;
	m_tree = new DSCSidebarView(frame, view, this);
	m_model = new DSCFilterModel(view);
	m_tree->setDragDropMode(QAbstractItemView::DragDrop);
	m_tree->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_tree->setDragEnabled(true);
	m_tree->setAcceptDrops(true);
	m_tree->setDropIndicatorShown(true);
	m_tree->header()->setSectionsMovable(false);

	m_tree->setModel(m_model);
	m_model->setRecursiveFilteringEnabled(true);

	m_filterEdit = new FilterEdit(this);
	m_filterView = new FilteredView(this, m_tree, this, m_filterEdit);
	m_filterView->setFilterPlaceholderText("Search Shared Cache Files");

	auto headerLayout = new QHBoxLayout(m_header);
	headerLayout->setContentsMargins(0, 0, 0, 0);
	headerLayout->addWidget(m_filterEdit);

	auto layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(m_filterView);
}

//===-- ComponentTree - FilterTarget --------------------------------------===//

void DSCSidebarWidget::setFilter(const std::string& filter)
{
	m_model->setFilterFixedString(QString::fromStdString(filter));
}

void DSCSidebarWidget::scrollToFirstItem() {}

void DSCSidebarWidget::scrollToCurrentItem() {}

void DSCSidebarWidget::selectFirstItem() {}

void DSCSidebarWidget::activateFirstItem() {}

//===-- DSCSidebarWidget - SidebarWidget -------------------------------------===//

QWidget* DSCSidebarWidget::headerWidget()
{
	return m_header;
}

void DSCSidebarWidget::focus() {}

QImage temporaryIcon()
{
	QImage icon(56, 56, QImage::Format_RGB32);
	icon.fill(0);

	QPainter p;
	p.begin(&icon);
	p.setFont({"Inter", 16});
	p.setPen({255, 255, 255, 255});
	p.drawText(QRectF {0, 0, 56, 56}, Qt::AlignCenter, "DSC");
	p.end();

	return icon;
}

DSCSidebarWidgetType::DSCSidebarWidgetType() : SidebarWidgetType(temporaryIcon(), "Shared Cache") {}

SidebarWidget* DSCSidebarWidgetType::createWidget(ViewFrame* frame, BinaryViewRef data)
{
	return new DSCSidebarWidget(frame, data);
}
