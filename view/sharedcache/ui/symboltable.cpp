#include <progresstask.h>
#include "symboltable.h"

#include <QHeaderView>

#include "ui/fontsettings.h"

#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace SharedCacheAPI;

SymbolTableModel::SymbolTableModel(SymbolTableView* parent)
	: QAbstractTableModel(parent), m_parent(parent) {
	// TODO: Need to implement updating this font if it is changed by the user
	m_font = getMonospaceFont(parent);
}

int SymbolTableModel::rowCount(const QModelIndex& parent) const {
	Q_UNUSED(parent);
	return static_cast<int>(m_modelSymbols.size());
}

int SymbolTableModel::columnCount(const QModelIndex& parent) const {
	Q_UNUSED(parent);
	// We have 3 columns: Address, Type, Name
	return 3;
}

QVariant SymbolTableModel::data(const QModelIndex& index, int role) const {
	if (!index.isValid() || (role != Qt::DisplayRole && role != Qt::FontRole)) {
		return QVariant();
	}

	switch (role)
	{
	case Qt::DisplayRole:
	{
		auto symbol = symbolAt(index.row());
		auto symbolType = GetSymbolTypeAsString(symbol.type);

		switch (index.column())
		{
		case 0: // Address column
			return QString("0x%1").arg(symbol.address, 0, 16); // Display address as hexadecimal
		case 1: // Type column
			return QString::fromUtf8(symbolType.c_str(), symbolType.size());
		case 2: // Name column
			return QString::fromUtf8(symbol.name.c_str(), symbol.name.size());
		default:
			return QVariant();
		}
	}
	case Qt::FontRole:
		return m_font;
	default:
		return QVariant();
	}
}

QVariant SymbolTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
	if (role != Qt::DisplayRole || orientation != Qt::Horizontal) {
		return QVariant();
	}

	switch (section) {
	case 0:
		return QString("Address");
	case 1:
		return QString("Type");
	case 2:
		return QString("Name");
	default:
		return QVariant();
	}
}

void SymbolTableModel::updateSymbols(std::vector<CacheSymbol>&& symbols)
{
	m_preparedSymbols = symbols;
	setFilter(m_filter);
}

const CacheSymbol& SymbolTableModel::symbolAt(int row) const
{
	return m_modelSymbols.at(row);
}


void SymbolTableModel::setFilter(std::string text)
{
	beginResetModel();

	m_filter = text;
	m_modelSymbols = {};

	// Skip filtering if no filter applied.
	if (!m_filter.empty())
	{
		m_modelSymbols.reserve(m_preparedSymbols.size());
		for (const auto& symbol : m_preparedSymbols)
			if (((std::string_view)symbol.name).find(m_filter) != std::string::npos)
				m_modelSymbols.push_back(symbol);
		m_modelSymbols.shrink_to_fit();
	} else
	{
		m_modelSymbols = m_preparedSymbols;
	}

	endResetModel();
}


SymbolTableView::SymbolTableView(QWidget* parent)
	: m_model(new SymbolTableModel(this)) {

	// Set up the filter model
	setModel(m_model);

	// Configure view settings
	horizontalHeader()->setSectionResizeMode(0, QHeaderView::Fixed);
	horizontalHeader()->setSectionResizeMode(1, QHeaderView::Fixed);
	horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
	setEditTriggers(QAbstractItemView::NoEditTriggers);
	setSelectionBehavior(QAbstractItemView::SelectRows);
	setSelectionMode(QAbstractItemView::SingleSelection);
	verticalHeader()->setVisible(false);

	setSortingEnabled(true);
}

SymbolTableView::~SymbolTableView() {
	delete m_model;
}

void SymbolTableView::populateSymbols(BinaryView &view)
{
	if (auto controller = SharedCacheController::GetController(view)) {
		typedef std::vector<CacheSymbol> SymbolList;
		// Retrieve the symbols from the controller in a future than pass that to the model.
		QPointer<QFutureWatcher<SymbolList>> watcher = new QFutureWatcher<SymbolList>(this);
		connect(watcher, &QFutureWatcher<SymbolList>::finished, this, [watcher, this]() {
			if (watcher)
			{
				auto symbols = watcher->result();
				m_model->updateSymbols(std::move(symbols));
			}
		});
		QFuture<SymbolList> future = QtConcurrent::run([controller]() {
			return controller->GetSymbols();
		});
		watcher->setFuture(future);
		connect(this, &QObject::destroyed, this, [watcher]() {
			if (watcher && watcher->isRunning()) {
				watcher->cancel();
				watcher->waitForFinished();
			}
		});
	}
}

void SymbolTableView::setFilter(const std::string& filter) {
	m_model->setFilter(filter);
}
