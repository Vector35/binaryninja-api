#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtWidgets/QTreeView>
#include "filter.h"


struct ResourceEntry
{
	std::string type;
	uint64_t typeId;
	std::string name;
	uint64_t nameId;
	std::string language;
	uint64_t languageId;
	uint64_t dataRva;
	uint64_t dataSize;
	uint64_t dataAddress;
	uint64_t codepage;
	std::string preview;
};


class ResourcesModel : public QAbstractItemModel
{
	BinaryViewRef m_data;
	std::vector<ResourceEntry> m_allEntries, m_entries;
	int m_sortCol;
	Qt::SortOrder m_sortOrder;

	void performSort(int col, Qt::SortOrder order);

  public:
	enum Column
	{
		TypeCol = 0,
		NameCol = 1,
		LanguageCol = 2,
		SizeCol = 3,
		AddressCol = 4,
		PreviewCol = 5,
		ColumnCount = 6
	};

	ResourcesModel(QWidget* parent, BinaryViewRef data);

	virtual int columnCount(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent) const override;
	virtual QVariant data(const QModelIndex& index, int role) const override;
	virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
	virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
	virtual QModelIndex parent(const QModelIndex& index) const override;
	virtual void sort(int col, Qt::SortOrder order) override;
	void setFilter(const std::string& filterText, FilterOptions options);

	const ResourceEntry* getEntry(const QModelIndex& index) const;
	const std::vector<ResourceEntry>& getAllEntries() const { return m_allEntries; }
};


class TriageView;
class ResourcesWidget;

class ResourcesTreeView : public QTreeView, public FilterTarget
{
	BinaryViewRef m_data;
	ResourcesWidget* m_parent;
	TriageView* m_view;
	UIActionHandler m_actionHandler;
	ResourcesModel* m_model;

  public:
	ResourcesTreeView(ResourcesWidget* parent, TriageView* view, BinaryViewRef data);
	void copySelection();
	bool canCopySelection() const;
	void saveSelectedResource();
	void saveAllResources();

	virtual void setFilter(const std::string& filterText, FilterOptions options) override;
	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void ensureSelection() override;
	virtual void activateSelection() override;
	virtual void closeFilter() override;

  protected:
	virtual void keyPressEvent(QKeyEvent* event) override;

  private Q_SLOTS:
	void resourceSelected(const QModelIndex& cur, const QModelIndex& prev);
	void resourceDoubleClicked(const QModelIndex& cur);
};


class ResourcesWidget : public QWidget
{
	FilteredView* m_filter;

  public:
	ResourcesWidget(QWidget* parent, TriageView* view, BinaryViewRef data);
	void showFilter(const QString& filter);
};
