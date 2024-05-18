#pragma once

#include "render.h"
#include "sidebarwidget.h"
#include <qlistview.h>
#include <qsortfilterproxymodel.h>
#include <qstandarditemmodel.h>
#include <qstyleditemdelegate.h>


enum class HistoryOption
{
	ShowDates,
};


class BINARYNINJAUIAPI HistoryEntryItemModel : public QAbstractItemModel, public BinaryNinja::BinaryDataNotification, public UIContextNotification
{
	std::vector<UndoEntryRef> m_undoEntries;
	std::vector<UndoEntryRef> m_redoEntries;

	FileMetadataRef m_file;
	BinaryViewRef m_data;
	std::unordered_set<HistoryOption> m_options;
	QSettings m_settings;

	UndoEntryRef entryForRow(int row) const;

	QString getSettingKeyForOption(HistoryOption option) const;

	virtual void OnUndoEntryAdded(BinaryNinja::BinaryView* data, BinaryNinja::UndoEntry* entry) override;
	virtual void OnUndoEntryTaken(BinaryNinja::BinaryView* data, BinaryNinja::UndoEntry* entry) override;
	virtual void OnRedoEntryTaken(BinaryNinja::BinaryView* data, BinaryNinja::UndoEntry* entry) override;

	virtual void OnAfterSaveFile(UIContext* context, FileContext* file, ViewFrame* frame) override;

	void hardReload();

  public:
	HistoryEntryItemModel(QWidget* parent, BinaryViewRef data);
	~HistoryEntryItemModel();

	virtual QModelIndex index(int row, int column, const QModelIndex& parent = QModelIndex()) const override;
	virtual QModelIndex parent(const QModelIndex& child) const override;

	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override;

	virtual QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
	void toggleOption(HistoryOption option);
	bool isOptionSet(HistoryOption option);
};


class BINARYNINJAUIAPI HistoryEntryItemDelegate : public QStyledItemDelegate
{
	Q_OBJECT

	QFont m_font;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;

	RenderContext m_render;

  public:
	HistoryEntryItemDelegate(QWidget* parent = nullptr);

	void updateFonts();

	virtual void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override;
};


class BINARYNINJAUIAPI HistorySidebarWidget : public SidebarWidget
{
	Q_OBJECT
	QListView* m_entryList;
	HistoryEntryItemModel* m_model;
	HistoryEntryItemDelegate* m_itemDelegate;

	QWidget* m_header;
	BinaryViewRef m_data;
	bool m_updating = false;
	bool m_atBottom = true;

	virtual void contextMenuEvent(QContextMenuEvent*) override;

	void itemDoubleClicked(const QModelIndex& index);
	void scrollBarValueChanged(int value);
	void scrollBarRangeChanged(int min, int max);

	void resetToSelectedEntry(std::function<bool(size_t, size_t)> progress);

  public:
	HistorySidebarWidget(BinaryViewRef data);
	~HistorySidebarWidget();
	void notifyFontChanged() override;
	QWidget* headerWidget() override { return m_header; }
};


class BINARYNINJAUIAPI HistorySidebarWidgetType : public SidebarWidgetType
{
  public:
	HistorySidebarWidgetType();
	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::RightBottom; }
	SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }
};
