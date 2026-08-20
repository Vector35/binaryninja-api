#pragma once

#include "triagetable.h"

#include <memory>
#include <stdint.h>
#include <vector>


// A cache symbol together with the image and region it belongs to, resolved once at load so the
// Image column never has to binary search the regions per render, filter, or comparison.
struct SymbolRow
{
	SharedCacheAPI::CacheSymbol symbol;
	// Header address of the owning image, or 0 if the symbol is outside any image.
	uint64_t imageStart;
	// Start address of the owning region, or 0 if the symbol is outside any region.
	uint64_t regionStart;
};


class SymbolTableModel : public TriageTableRowsModel<SymbolRow>
{
public:
	// A region's address range, for resolving a symbol's address to the image or region
	// containing it.
	struct AddressRange
	{
		uint64_t start;
		uint64_t end;
		std::optional<uint64_t> imageStart;
	};

private:
	// Region address ranges sorted by start address, for resolving symbol addresses.
	std::shared_ptr<const std::vector<AddressRange>> m_ranges = std::make_shared<const std::vector<AddressRange>>();
	ImageNameLookup m_names;

	// The ascending three-way ordering for a column, or null if the column is not sortable.
	KeyOrdering orderingForColumn(int column) const override;

protected:
	void applyFilter() override;
	bool rowsEquivalent(const SymbolRow& a, const SymbolRow& b) const override;

public:
	explicit SymbolTableModel(QWidget* parent);

	int columnCount(const QModelIndex& parent) const override;
	QVariant data(const QModelIndex& index, int role) const override;
	QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

	// Build the Image column lookup tables and the address resolution ranges.
	void setNameSources(const SharedCacheAPI::SharedCacheController& controller);

	// Resolve each symbol's image and region once, then append them.
	void appendSymbols(std::vector<SharedCacheAPI::CacheSymbol> symbols);

	const ImageNameLookup& names() const { return m_names; }

	const SharedCacheAPI::CacheSymbol& symbolAt(int row) const { return rowAt(row).symbol; }
};


class SymbolTableView : public TriageTableView
{
	SymbolTableModel* m_model;

public:
	explicit SymbolTableView(QWidget* parent);

	SymbolTableModel* symbolsModel() const { return m_model; }

	// Build the Image column lookup tables and refit the default column widths.
	void setNameSources(const SharedCacheAPI::SharedCacheController& controller);

	SharedCacheAPI::CacheSymbol getSymbolAtRow(int row) const
	{
		return m_model->symbolAt(row);
	}

protected:
	void applyDefaultColumnWidths() override;
};
