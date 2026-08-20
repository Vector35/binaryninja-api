#include "stringstable.h"

#include "addresstext.h"
#include "theme.h"

#include <algorithm>
#include <memory>

using namespace SharedCacheAPI;

namespace {

enum StringsTableColumn
{
	StringsTableAddressColumn,
	StringsTableTypeColumn,
	StringsTableLengthColumn,
	StringsTableImageColumn,
	StringsTableStringColumn,
	StringsTableColumnCount,
};

QString StringTypeAsString(BNStringType type)
{
	switch (type)
	{
	case AsciiString:
		return QStringLiteral("ASCII");
	case Utf8String:
		return QStringLiteral("UTF-8");
	case Utf16String:
		return QStringLiteral("UTF-16");
	case Utf32String:
		return QStringLiteral("UTF-32");
	default:
		return QStringLiteral("Unknown");
	}
}

QString DisplayTextForString(const CacheString& string)
{
	QString text = QString::fromUtf8(string.text.c_str(), string.text.size());
	text.replace('\n', QStringLiteral("\\n"));
	text.replace('\r', QStringLiteral("\\r"));
	text.replace('\t', QStringLiteral("\\t"));
	return text;
}


// The image lookup key for a string, or nullopt when the string is outside any image.
std::optional<uint64_t> ImageKey(const CacheString& string)
{
	if (string.imageStart == 0)
		return std::nullopt;
	return string.imageStart;
}

QString ImageNameForString(const ImageNameLookup::State& names, const CacheString& string)
{
	return ImageNameLookup::displayName(names, ImageKey(string), string.regionStart);
}

}  // namespace


StringsTableModel::StringsTableModel(QWidget* parent) : TriageTableRowsModel(parent)
{
	m_finalComparator = [](const CacheString& a, const CacheString& b) { return a.address < b.address; };
	// Establish the initial row visibility. Non-image strings are hidden by default.
	applyFilter();
}


int StringsTableModel::columnCount(const QModelIndex& parent) const
{
	Q_UNUSED(parent);
	return StringsTableColumnCount;
}


QVariant StringsTableModel::data(const QModelIndex& index, int role) const
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
		const auto& string = stringAt(index.row());

		switch (index.column())
		{
		case StringsTableAddressColumn:
			return QString::fromStdString(AddressText(string.address, m_addressWidth));
		case StringsTableTypeColumn:
			return StringTypeAsString(string.type);
		case StringsTableLengthColumn:
			return QString::number(string.rawLength);
		case StringsTableImageColumn:
			return ImageNameForString(*m_names.snapshot(), string);
		case StringsTableStringColumn:
			return DisplayTextForString(string);
		default:
			return QVariant();
		}
	}
	case Qt::ForegroundRole:
		switch (index.column())
		{
		case StringsTableAddressColumn:
			return getThemeColor(AddressColor);
		case StringsTableTypeColumn:
			return getThemeColor(TypeNameColor);
		case StringsTableLengthColumn:
			return getThemeColor(NumberColor);
		case StringsTableStringColumn:
			return getThemeColor(StringColor);
		default:
			return QVariant();
		}
	case Qt::ToolTipRole:
	{
		if (index.column() != StringsTableImageColumn)
			return QVariant();
		const auto& string = stringAt(index.row());
		if (QString tooltip = m_names.tooltip(ImageKey(string), string.regionStart); !tooltip.isEmpty())
			return tooltip;
		return QVariant();
	}
	case Qt::FontRole:
		return m_font;
	default:
		return QVariant();
	}
}


QVariant StringsTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
	if (role != Qt::DisplayRole || orientation != Qt::Horizontal)
		return QVariant();

	switch (section)
	{
	case StringsTableAddressColumn:
		return QString("Address");
	case StringsTableTypeColumn:
		return QString("Type");
	case StringsTableLengthColumn:
		return QString("Length");
	case StringsTableImageColumn:
		return QString("Image");
	case StringsTableStringColumn:
		return QString("String");
	default:
		return QVariant();
	}
}


StringsTableModel::KeyOrdering StringsTableModel::orderingForColumn(int column) const
{
	switch (column)
	{
	case StringsTableAddressColumn:
		return [](const CacheString& a, const CacheString& b) { return a.address <=> b.address; };
	case StringsTableTypeColumn:
		return [](const CacheString& a, const CacheString& b) { return a.type <=> b.type; };
	case StringsTableLengthColumn:
		return [](const CacheString& a, const CacheString& b) { return a.rawLength <=> b.rawLength; };
	case StringsTableStringColumn:
		return [](const CacheString& a, const CacheString& b) { return a.text <=> b.text; };
	case StringsTableImageColumn:
		return ImageColumnOrdering<CacheString>(*m_names.snapshot());
	default:
		return nullptr;
	}
}


void StringsTableModel::setNameSources(const SharedCacheController& controller)
{
	m_names.build(controller);
	m_addressWidth = BNGetAddressRenderedWidth(m_names.maxAddress());
}


void StringsTableModel::appendStrings(std::vector<CacheString> strings)
{
	m_imageStringCount += std::ranges::count_if(
		strings, [](const CacheString& string) { return string.imageStart != 0; });
	appendRows(std::move(strings));
}


void StringsTableModel::clearRows()
{
	m_imageStringCount = 0;
	TriageTableRowsModel::clearRows();
}


void StringsTableModel::setShowNonImageStrings(bool show)
{
	if (m_showNonImageStrings == show)
		return;
	m_showNonImageStrings = show;
	applyFilter();
}


bool StringsTableModel::rowsEquivalent(const CacheString& a, const CacheString& b) const
{
	return a.address == b.address;
}


void StringsTableModel::applyFilter()
{
	if (m_filterText.empty() && m_showNonImageStrings)
	{
		m_rows.setFilter(nullptr);
		return;
	}

	const auto snapshot = filterSnapshot();
	const uint32_t addressWidth = m_addressWidth;
	const auto names = m_names.snapshot();

	m_rows.setFilterFactory(
		[snapshot, addressWidth, names, showNonImageStrings = m_showNonImageStrings]() -> Predicate {
			FilterParams params = MakeFilterParams(snapshot);
			return [params = std::move(params), addressWidth, names, showNonImageStrings](const CacheString& string) {
				if (!showNonImageStrings && !string.imageStart)
					return false;
				if (params.text.empty())
					return true;
				QString imageName;
				if (params.matchImageNames)
					imageName = ImageNameForString(*names, string);
				return MatchesText(params, string.text, string.address, addressWidth, imageName);
			};
		});
}


StringsTableView::StringsTableView(QWidget* parent) : TriageTableView(parent)
{
	m_model = new StringsTableModel(this);
	setTriageModel(m_model, StringsTableAddressColumn);
	applyDefaultColumnWidths();
}


void StringsTableView::setNameSources(const SharedCacheController& controller)
{
	m_model->setNameSources(controller);
	applyDefaultColumnWidths();
}


void StringsTableView::applyDefaultColumnWidths()
{
	fitColumn(StringsTableAddressColumn, {QString(m_model->addressWidth(), QChar('0'))});
	fitColumn(StringsTableTypeColumn,
		{StringTypeAsString(AsciiString), StringTypeAsString(Utf8String), StringTypeAsString(Utf16String),
			StringTypeAsString(Utf32String)});
	fitColumn(StringsTableLengthColumn, {});
	fitColumn(StringsTableImageColumn, {m_model->names().widestImageColumnText()});
}
