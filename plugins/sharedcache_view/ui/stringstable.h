#pragma once

#include "triagetable.h"


class StringsTableModel : public TriageTableRowsModel<SharedCacheAPI::CacheString>
{
	ImageNameLookup m_names;
	bool m_showNonImageStrings = false;
	size_t m_imageStringCount = 0;

	// The ascending three-way ordering for a column, or null if the column is not sortable.
	KeyOrdering orderingForColumn(int column) const override;

protected:
	void applyFilter() override;
	bool rowsEquivalent(
		const SharedCacheAPI::CacheString& a, const SharedCacheAPI::CacheString& b) const override;

public:
	explicit StringsTableModel(QWidget* parent);

	int columnCount(const QModelIndex& parent) const override;
	QVariant data(const QModelIndex& index, int role) const override;
	QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

	// Build the Image column lookup tables.
	void setNameSources(const SharedCacheAPI::SharedCacheController& controller);

	const ImageNameLookup& names() const { return m_names; }

	// Append a batch of scan results, filtering only the new rows.
	void appendStrings(std::vector<SharedCacheAPI::CacheString> strings);

	void clearRows() override;

	// Whether strings in regions not belonging to any image are shown.
	void setShowNonImageStrings(bool show);

	// Count of strings eligible for display under the current visibility options, ignoring any
	// text filter.
	size_t baselineStringCount() const
	{
		return m_showNonImageStrings ? totalRowCount() : m_imageStringCount;
	}

	const SharedCacheAPI::CacheString& stringAt(int row) const { return rowAt(row); }
};


class StringsTableView : public TriageTableView
{
	StringsTableModel* m_model;

public:
	explicit StringsTableView(QWidget* parent);

	StringsTableModel* stringsModel() const { return m_model; }

	// Build the Image column lookup tables and refit the default column widths.
	void setNameSources(const SharedCacheAPI::SharedCacheController& controller);

	SharedCacheAPI::CacheString getStringAtRow(int row) const
	{
		return m_model->stringAt(row);
	}

protected:
	void applyDefaultColumnWidths() override;
};
