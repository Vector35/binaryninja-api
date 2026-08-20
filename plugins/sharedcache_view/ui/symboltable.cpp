#include "symboltable.h"

#include "addresstext.h"
#include "theme.h"

#include <algorithm>
#include <memory>

using namespace SharedCacheAPI;

namespace {

enum SymbolsTableColumn
{
	SymbolsTableAddressColumn,
	SymbolsTableTypeColumn,
	SymbolsTableImageColumn,
	SymbolsTableNameColumn,
	SymbolsTableColumnCount,
};

QString SymbolTypeAsString(BNSymbolType type)
{
	const std::string name = GetSymbolTypeAsString(type);
	return QString::fromUtf8(name.c_str(), name.size());
}


const SymbolTableModel::AddressRange* RangeContaining(
	const std::vector<SymbolTableModel::AddressRange>& ranges, uint64_t address)
{
	auto it = std::upper_bound(ranges.begin(), ranges.end(), address,
		[](uint64_t address, const SymbolTableModel::AddressRange& range) {
			return address < range.start;
		});
	if (it == ranges.begin())
		return nullptr;
	--it;
	if (address >= it->end)
		return nullptr;
	return &*it;
}


// The image lookup key for a row, or nullopt when the symbol is outside any image.
std::optional<uint64_t> ImageKey(const SymbolRow& row)
{
	if (row.imageStart == 0)
		return std::nullopt;
	return row.imageStart;
}

QString ImageNameForSymbol(const ImageNameLookup::State& names, const SymbolRow& row)
{
	return ImageNameLookup::displayName(names, ImageKey(row), row.regionStart);
}

}  // namespace


SymbolTableModel::SymbolTableModel(QWidget* parent) : TriageTableRowsModel(parent)
{
	m_finalComparator = [](const SymbolRow& a, const SymbolRow& b) { return a.symbol.address < b.symbol.address; };
}


int SymbolTableModel::columnCount(const QModelIndex& parent) const
{
	Q_UNUSED(parent);
	return SymbolsTableColumnCount;
}


QVariant SymbolTableModel::data(const QModelIndex& index, int role) const
{
	if (!index.isValid())
		return QVariant();

	const size_t row = static_cast<size_t>(index.row());
	BN_ASSERT(row < m_rows.displayCount());
	if (row >= m_rows.displayCount())
		return QVariant();

	switch (role)
	{
	case Qt::DisplayRole:
	{
		const auto& symbolRow = rowAt(index.row());
		const auto& symbol = symbolRow.symbol;

		switch (index.column())
		{
		case SymbolsTableAddressColumn:
			return QString::fromStdString(AddressText(symbol.address, m_addressWidth));
		case SymbolsTableTypeColumn:
			return SymbolTypeAsString(symbol.type);
		case SymbolsTableImageColumn:
			return ImageNameForSymbol(*m_names.snapshot(), symbolRow);
		case SymbolsTableNameColumn:
			return QString::fromUtf8(symbol.name.c_str(), symbol.name.size());
		default:
			return QVariant();
		}
	}
	case Qt::ForegroundRole:
		switch (index.column())
		{
		case SymbolsTableAddressColumn:
			return getThemeColor(AddressColor);
		case SymbolsTableTypeColumn:
			return getThemeColor(TypeNameColor);
		case SymbolsTableNameColumn:
			switch (symbolAt(index.row()).type)
			{
			case FunctionSymbol:
				return getThemeColor(CodeSymbolColor);
			case DataSymbol:
				return getThemeColor(DataSymbolColor);
			default:
				return QVariant();
			}
		default:
			return QVariant();
		}
	case Qt::ToolTipRole:
	{
		if (index.column() != SymbolsTableImageColumn)
			return QVariant();
		const auto& symbolRow = rowAt(index.row());
		if (QString tooltip = m_names.tooltip(ImageKey(symbolRow), symbolRow.regionStart); !tooltip.isEmpty())
			return tooltip;
		return QVariant();
	}
	case Qt::FontRole:
		return m_font;
	default:
		return QVariant();
	}
}


QVariant SymbolTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
	if (role != Qt::DisplayRole || orientation != Qt::Horizontal)
		return QVariant();

	switch (section)
	{
	case SymbolsTableAddressColumn:
		return QString("Address");
	case SymbolsTableTypeColumn:
		return QString("Type");
	case SymbolsTableImageColumn:
		return QString("Image");
	case SymbolsTableNameColumn:
		return QString("Name");
	default:
		return QVariant();
	}
}


SymbolTableModel::KeyOrdering SymbolTableModel::orderingForColumn(int column) const
{
	switch (column)
	{
	case SymbolsTableAddressColumn:
		return [](const SymbolRow& a, const SymbolRow& b) { return a.symbol.address <=> b.symbol.address; };
	case SymbolsTableTypeColumn:
		return [](const SymbolRow& a, const SymbolRow& b) { return a.symbol.type <=> b.symbol.type; };
	case SymbolsTableNameColumn:
		return [](const SymbolRow& a, const SymbolRow& b) { return a.symbol.name <=> b.symbol.name; };
	case SymbolsTableImageColumn:
		return ImageColumnOrdering<SymbolRow>(*m_names.snapshot());
	default:
		return nullptr;
	}
}


void SymbolTableModel::setNameSources(const SharedCacheController& controller)
{
	m_names.build(controller);
	m_addressWidth = BNGetAddressRenderedWidth(m_names.maxAddress());

	auto ranges = std::make_shared<std::vector<AddressRange>>();
	for (const auto& region : controller.GetRegions())
		ranges->push_back({region.start, region.start + region.size, region.imageStart});
	std::sort(ranges->begin(), ranges->end(),
		[](const AddressRange& a, const AddressRange& b) { return a.start < b.start; });
	m_ranges = std::move(ranges);
}


void SymbolTableModel::appendSymbols(std::vector<CacheSymbol> symbols)
{
	std::vector<SymbolRow> rows;
	rows.reserve(symbols.size());
	for (auto& symbol : symbols)
	{
		const auto* range = RangeContaining(*m_ranges, symbol.address);
		rows.push_back({std::move(symbol), range ? range->imageStart.value_or(0) : 0,
			range ? range->start : 0});
	}
	appendRows(std::move(rows));
}


bool SymbolTableModel::rowsEquivalent(const SymbolRow& a, const SymbolRow& b) const
{
	return a.symbol.address == b.symbol.address && a.symbol.name == b.symbol.name;
}


void SymbolTableModel::applyFilter()
{
	if (m_filterText.empty())
	{
		m_rows.setFilter(nullptr);
		return;
	}

	const auto snapshot = filterSnapshot();
	const uint32_t addressWidth = m_addressWidth;
	const auto names = m_names.snapshot();

	m_rows.setFilterFactory([snapshot, addressWidth, names]() -> Predicate {
		FilterParams params = MakeFilterParams(snapshot);
		return [params = std::move(params), addressWidth, names](const SymbolRow& row) {
			QString imageName;
			if (params.matchImageNames)
				imageName = ImageNameForSymbol(*names, row);
			return MatchesText(params, row.symbol.name, row.symbol.address, addressWidth, imageName);
		};
	});
}


SymbolTableView::SymbolTableView(QWidget* parent) : TriageTableView(parent)
{
	m_model = new SymbolTableModel(this);
	setTriageModel(m_model, SymbolsTableAddressColumn);
	applyDefaultColumnWidths();
}


void SymbolTableView::setNameSources(const SharedCacheController& controller)
{
	m_model->setNameSources(controller);
	applyDefaultColumnWidths();
}


void SymbolTableView::applyDefaultColumnWidths()
{
	fitColumn(SymbolsTableAddressColumn, {QString(m_model->addressWidth(), QChar('0'))});
	fitColumn(SymbolsTableTypeColumn,
		{SymbolTypeAsString(FunctionSymbol), SymbolTypeAsString(DataSymbol), QStringLiteral("Unknown")});
	fitColumn(SymbolsTableImageColumn, {m_model->names().widestImageColumnText()});
}
