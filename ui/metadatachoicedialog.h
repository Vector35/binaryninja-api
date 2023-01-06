#pragma once

#include <QtWidgets>
#include <ui/filter.h>

/*! \defgroup metadatachoicedialog MetadataChoiceDialog
	\ingroup uiapi

	MetadataChoiceDialog aims to provide a fairly extensible dialog for displaying selection info, without
 		requiring reimplementation or extra UI code whenever complex behavior is required.

	It can optionally display metadata to the right, a 2nd column with extra information about entries,
		and can have a checkbox-toggleable second filter (the first one being a regular text filter bar).

	These are all described in the class documentation below.
*/

/*!
	\ingroup metadatachoicedialog
*/
struct EntryItem {
	size_t idx;
	QString entryText;
};


/*!
    \ingroup metadatachoicedialog
*/
class ManagedTableDelegate {
public:
	// model
	virtual size_t ManagedTableColumnCount() = 0;
	virtual size_t ManagedTableRowCount() = 0;
	virtual QString ManagedTableColumnName(size_t) = 0;
	virtual QString ManagedTableDisplayText(size_t row, size_t col) = 0;
	// view
	virtual std::vector<std::pair<QString, std::function<void(EntryItem item)>>> GetTableContextMenuItems() = 0;
	virtual void ExecuteContextMenuItem(size_t menuItemIndex, size_t idx) = 0;
	virtual std::vector<EntryItem> GetAllItems() const = 0;
	virtual bool EntryItemPassesExtraFilters(EntryItem& item) = 0;
};

// Model that is blind and queries info from its delegate.
class ManagedTableModel : public QAbstractTableModel
{
	ManagedTableDelegate* m_delegate;


	QVariant headerData(int, Qt::Orientation, int role = Qt::DisplayRole) const override;
	QVariant data(const QModelIndex&, int role = Qt::DisplayRole) const override;

	int rowCount(const QModelIndex& parent = QModelIndex()) const override { return m_delegate->ManagedTableRowCount(); };
	int columnCount(const QModelIndex& parent = QModelIndex()) const override { return m_delegate->ManagedTableColumnCount(); };
public:
	void resetModel();
	QModelIndex index(int row, int column, const QModelIndex& parentIndex) const override;

	void SetDelegate(ManagedTableDelegate* delegate) { m_delegate = delegate; };
};

class ManagedTableView : public QTableView, public FilterTarget
{
	Q_OBJECT

	ManagedTableModel* m_model;

	std::string m_filter;

	ManagedTableDelegate* m_delegate;

	QWidget* m_tabChainPrefixWidget;
	QWidget* m_tabChainSuffixWidget;

public:
	ManagedTableView(QWidget* parent, const QStringList& entries);
	size_t getCurrentSelection();

	void forceFilterUpdate() {
		setFilter(m_filter);
	};

	void resetModel();

	void setFocusPrefixWidget(QWidget* wdgt) { m_tabChainPrefixWidget = wdgt; };
	void setFocusSuffixWidget(QWidget* wdgt) { m_tabChainSuffixWidget = wdgt; };

	virtual void selectionChanged(const QItemSelection& selected, const QItemSelection& deselected) override;

	virtual void setFilter(const std::string& filter) override;
	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void selectFirstItem() override;
	virtual void activateFirstItem() override;

	virtual void focusInEvent(QFocusEvent *event) override;
	bool focusNextPrevChild(bool next) override;
	void contextMenuEvent(QContextMenuEvent *event) override;

	void SetDelegate(ManagedTableDelegate*);

signals:
	void selectionModified(size_t idx);
};


constexpr size_t maximumMetadataTextLineCount = 506; // Enough for 500 entries and 6 lines for any truncation indications.


enum MetadataMode {
	PlaintextMetadataMode,
	DisassemblyTextLineMetadataMode
};


class EntryItemMetadataViewDelegate {
public:
	virtual MetadataMode GetCurrentMode() = 0;
	virtual std::vector<BinaryNinja::DisassemblyTextLine> LinesForEntryItem(EntryItem& item) = 0;
	virtual QString PlaintextForEntryItem(EntryItem& item) = 0;
};


/*!
    \ingroup metadatachoicedialog
*/
class EntryItemMetadataView : public QTextEdit
{
	EntryItemMetadataViewDelegate* m_delegate;

protected:
	bool m_currentItemIsTruncated;

public:
	explicit EntryItemMetadataView(QWidget* parent);
	void SetDelegate(EntryItemMetadataViewDelegate* delegate) { m_delegate = delegate; };

	virtual void DisplayPlainText(EntryItem& item);
	virtual void DisplayTextLines(EntryItem& item);
};



/*! MetadataChoiceDialog is a dynamic UI View and Controller that allows the user to make a selection given a list of
		entries, and metadata about those entries.

	The Model's data is left up to the developer using the dialog to manage. A developer can implement a second
		checkbox-toggled filter, custom metadata shown in a box to the right of the table, and/or a custom second column
		with additional info about entries.

	Content from all of these callbacks is cached, however these caches can be evicted if data has changed or been added.

	This dialog can to scale to very large amounts of arbitrary info by lazily loading it from provided callbacks, without
		requiring bespoke dialogs being built for those applications.

	\b Example:
	\code{.cpp}
	// In this example, we display a list of all defined types to the user and allow them to pick one.
	QStringList entries;
	std::vector<TypeRef> entryTypes;

	for (auto type : bv->GetTypes())
	{
		entries.push_back(QString::fromStdString(type.first.GetString()));
		entryTypes.push_back(type.second);
	}

	auto choiceDialog = new MetadataChoiceDialog(parent, "Pick Type", entries);

	// For our metadata, we'll just print the type definition. You could also have this callback return just a QString,
	// 		but we want the type tokens to have syntax highlighting here.
	std::function<std::vector<BinaryNinja::DisassemblyTextLine>(EntryItem item)> getMetadata =
		[&](EntryItem item)
		{
			TypeRef type = entryTypes.at(item.idx);
			std::vector<BinaryNinja::DisassemblyTextLine> metadata;

			for (auto line : type->GetLines(data, entries.at(item.idx).toStdString()))
			{
				DisassemblyTextLine l;
				l.tokens = line.tokens;
				metadata.push_back(l);
			}

			return metadata;
		};
	choiceDialog->SetMetadataCallback(getMetadata);

	// For our checkbox filter, we'll allow the user to filter out non-enum types.
	std::function<bool(EntryItem item)> isEntryEnum =
		[&](EntryItem item)
		{
			TypeRef type = entryTypes.at(item.idx);
			return (type.second->IsEnumeration() || type.second->IsEnumReference());
		};
	choiceDialog->SetExtraFilter("Hide non-enums", isEntryEnum);

	// For our second column, we'll show the width of the type.
	std::function<QString(EntryItem item)> secondColumnText =
		[&](EntryItem item)
		{
			TypeRef type = entryTypes.at(item.idx);
			return "0x" + QString::number(type->GetWidth(), 16);
		};
	choiceDialog->SetSecondColumnTextCallback("Type Width", secondColumnText);

	choiceDialog->exec();

	if (choiceDialog->GetChosenEntry().has_value())
		return entryTypes.at(choiceDialog->GetChosenEntry().value().idx);
	else
		return nullptr;
	\endcode

	AddContextButton and AddContextMenuItem can also be used for more complex UI behavior if required, and examples
		are provided for using those in their respective documentation.
	There are also several methods for adding or
		editing entries, evicting caches, and so on, if you need to modify the dialog's contents on the fly via a button
		or context menu item.

	\ingroup metadatachoicedialog
*/
class MetadataChoiceDialog : public QDialog, public ManagedTableDelegate, public EntryItemMetadataViewDelegate {
	Q_OBJECT

protected:

	std::vector<EntryItem> m_entries;


	QHBoxLayout* m_midRowLayout;

	// ManagedTableDelegate
	virtual size_t ManagedTableColumnCount() override;
	virtual size_t ManagedTableRowCount() override;
	virtual QString ManagedTableColumnName(size_t) override;
	virtual QString ManagedTableDisplayText(size_t row, size_t col) override;

	virtual std::vector<std::pair<QString, std::function<void(EntryItem item)>>> GetTableContextMenuItems() override
		{ return m_contextMenuItems; };
	virtual void ExecuteContextMenuItem(size_t menuItemIndex, size_t idx) override;
	virtual bool EntryItemPassesExtraFilters(EntryItem& item) override;
	virtual std::vector<EntryItem> GetAllItems() const { return m_entries; };

	struct ExtraFilterState {
		bool exists = false;
		bool enabled = false;
		bool cacheEnabled = true;
		QString title;
		std::unordered_map<size_t, bool> cache;
		std::function<bool(EntryItem item)> callback;
	};

	struct MetadataState {
		bool exists = false;
		bool cacheEnabled = true;
		MetadataMode mode;
		std::unordered_map<size_t, QString> preloadedPlaintext;
		std::unordered_map<size_t, std::vector<BinaryNinja::DisassemblyTextLine>> preloadedTextLines;
		std::unordered_map<size_t, QString> plaintextCache;
		std::unordered_map<size_t, std::vector<BinaryNinja::DisassemblyTextLine>> disassemblyTextLineCache;
		std::function<QString(EntryItem item)> plaintextCallback;
		std::function<std::vector<BinaryNinja::DisassemblyTextLine>(EntryItem item)> disassemblyTextLineCallback;
	};

	// EntryItemMetadataViewDelegate
	virtual MetadataMode GetCurrentMode() override { return m_metadata.mode; };
	virtual std::vector<BinaryNinja::DisassemblyTextLine> LinesForEntryItem(EntryItem& item) override;
	virtual QString PlaintextForEntryItem(EntryItem& item) override;

	bool m_secondColumnCacheEnabled = true;
	struct InfoColumn {
		QString name;
		std::unordered_map<size_t, QString> textCache;
		std::function<QString(EntryItem& item)> textCallback;
	};

	std::vector<InfoColumn> m_infoColumns;

	std::vector<std::pair<QString, std::function<void(EntryItem item)>>> m_contextMenuItems;

	ManagedTableView* m_entryListView;
	EntryItemMetadataView* m_metadataView;
	FilteredView* m_filterView;
	FilterEdit* m_edit;

	MetadataState m_metadata;

	// Allows a custom checkbox to toggle some condition that items must also pass after passing the search filter.
	QCheckBox* m_extraFilterCheckbox;
	ExtraFilterState m_extraFilter;

	QLabel* m_selectedText;
	QPushButton* m_cancel;
	QPushButton* m_choose;

	bool ExtraFilterEnabled() { return m_extraFilter.exists && m_extraFilter.enabled; };

	void AddWidthRequiredByItem(void* item, size_t widthRequired);
	void RemoveWidthRequiredByItem(QWidget* item);
	void AddHeightRequiredByItem(void* item, size_t widthRequired);
	void RemoveHeightRequiredByItem(QWidget* item);
	void UpdateMinimumSpace();

	std::optional<EntryItem> m_chosenEntry;
	EntryItem m_selectedEntry;

private:

	void UpdateMetadataBox(EntryItem& item);

	QHBoxLayout* m_bottomLeftRowLayout;
	QHBoxLayout* m_entryTableContextButtonLayout;

	std::unordered_map<void*, size_t> m_layoutWidthRequiringItems;
	std::unordered_map<void*, size_t> m_layoutHeightRequiringItems;


public:
	/*! Create a choice selection dialog with a Title, list of entries, and pre-built set of metadata for those entries.

		\note For large amounts of entries, where computing the metadata for all of them may take a while, it is
		highly recommended that instead of passing prebuilt metadata, a callback that lazily loads it should be used instead

		\see SetMetadataCallback

		\param parent Parent Widget
		\param title Title of the dialog
		\param entries List of entries
		\param metadata Map of indices to the metadata for those entries.
	*/
	MetadataChoiceDialog(QWidget* parent, const QString& title, const QStringList& entries,
		std::unordered_map<size_t, QString> metadata);

	/*! Create a choice selection dialog with a Title, list of entries, and pre-built set of metadata for those entries.

		\note For large amounts of entries, where computing the metadata for all of them may take a while, it is
		highly recommended that instead of passing prebuilt metadata, a callback that lazily loads it should be used instead

		\see SetMetadataCallback

		\param parent Parent Widget
		\param title Title of the dialog
		\param entries List of entries
		\param metadata Map of indices to the metadata (as InstructionTextTokens) for those entries.
	*/
	MetadataChoiceDialog(QWidget* parent, const QString& title, const QStringList& entries,
		std::unordered_map<size_t, std::vector<BinaryNinja::DisassemblyTextLine>> metadata);

	/*! Create a choice selection dialog with a Title and list of entries.

		\note Without setting a Metadata Callback, metadata will not be displayed for the entries in the view.

		\param parent Parent Widget
		\param title Title of the dialog
		\param entries List of entries
	*/
	MetadataChoiceDialog(QWidget* parent, const QString& title, const QStringList& entries);

	MetadataChoiceDialog(QWidget* parent, const QString& title) :
		MetadataChoiceDialog(parent, title, {}) {}

	/*! Set the callback the dialog will execute to retrieve metadata for a given item.

		\param callback Non nullable function (can be a lambda) that returns a QString containing metadata about the
		given EntryItem
	*/
	void SetMetadataCallback(const std::function<QString(EntryItem item)>& callback);

	/*! Set the callback the dialog will execute to retrieve metadata for a given item.

		\param callback Non nullable function (can be a lambda) that returns a vector of DisassemblyTextLines.
	*/
	void SetMetadataCallback(const std::function<std::vector<BinaryNinja::DisassemblyTextLine>(EntryItem item)>& callback);

	/*! Set the callback the dialog will execute to retrieve second column text for a given item.

		\code{.cpp}

		auto choiceDialog = new MetadataChoiceDialog(parent, "Select Enum", entries);

		// Set up everything else with dialog
		// ...
		uint64_t targetValue = 0x64;

		std::function<QString(EntryItem item)> getSecondColumnText =
			[&](EntryItem item)
		{
			TypeRef type = entryTypes.at(item.idx);

			for (auto member : type->GetEnumeration()->GetMembers()) // Look for an enum member with a value of 0x64
				if (member.value == targetValue)
					return QString::fromStdString(member.name);

			// If we cant find a member with a value of 0x64, just show 0x64 in the second column.
			return "0x" + QString::number(canTruncate ? constrainedValue : constValue, 16);
		};

		choiceDialog->SetSecondColumnTextCallback("Enum Member Name", getSecondColumnText);

		\endcode

		\param secondColumnTitle Title for the 2nd column
		\param callback Non nullable function (can be a lambda) that returns a QString containing optional second column
		text for the given index
	*/
	void AddColumn(QString columnTitle, const std::function<QString(EntryItem item)>& callback);

	/*! Set a callback for any optional extra conditions that entries must pass to be displayed. The user will be
		able to toggle this filter via a checkbox.

		\param filterTitle Title for the checkbox to toggle this filter condition.
		\param callback Callback function that checks whether a given entry index passes the extra filter.
	*/
	void SetExtraFilter(QString filterTitle, const std::function<bool(EntryItem item)> callback);

	/*! Set whether metadata should be cached after calling the metadata callback once. By default this is enabled.

		\param s Whether to cache metadata.
	*/
	void SetShouldCacheMetadata(bool s) { m_metadata.cacheEnabled = s; };

	/*! Set whether the entries that pass the extra filter should be cached. By default this is enabled.

		If the qualifications of the extra filter cannot change while this dialog is visible, this should be kept enabled.

		\param s Whether to cache extra filter results.
	*/
	void SetShouldCacheExtraFilterResults(bool s) { m_extraFilter.cacheEnabled = s; };

	/*! Get the chosen entry.

		Should be called after ->exec() has finished.

		\code{.cpp}
		// Do all of the initial view setup (see top of this page for a full overview.)

		choiceDialog->exec();

		if (choiceDialog->GetChosenEntry().has_value())
		{
			// EntryItem contains a string (with the entry) and an index.
			// But since we know the dialog maintains order of indices, we can skip string comparisons
			//		and just look it up by index.
			return entryTypes.at(choiceDialog->GetChosenEntry().value().idx);
		}
		return nullptr;

		\endcode

		\return The chosen entry, if one was chosen, or std::nullopt if selection was canceled.
	*/
	std::optional<EntryItem> GetChosenEntry() const { return m_chosenEntry; };

	/*! Add entries to the initial set.

		\note Don't use this for initial setup; it should primarily be used for any updates made while the dialog is open
				(via a button or other means).

		\note This will invalidate all caches, including any metadata initially passed in. If you need to add entries
			after opening the dialog and want metadata, you will need to use a callback.

		\param entries List of entries to add.
	*/
	void AddEntries(QStringList& entries);

	/*! Clear all caches.

		\note Calling AddEntries will also clear the caches.
	*/
	void InvalidateAllCaches();

	/*! Add a button (or other widget) to the right side of the search bar. You are responsible for the behavior of
		this widget.

		\b Example:
		\code{.cpp}
		// The icon we're using here is just the "add types" icon from the Types sidebar widget.
		ClickableIcon* addIcon = new ClickableIcon(QImage(":/icons/images/add.png"), QSize(16, 16));

		// This assumes we're not running within a class. If you are within another widget, use normal (icon, &method, this, &method2) syntax.
		QObject::connect(addIcon, &ClickableIcon::clicked,
	 		[&](){
				// Do something interesting. Here we're just going to ask for a new entry.
				std::string result;
				GetTextLineInput(result, "Enter a new entry:", "Enter Entry");

				// If you need to update your callbacks/info with the new entry, do so here, before you add it to the dialog.

				// Add the entry to the choice dialog.
				QStringList newEntries = { QString::fromStdString(result) };
				choiceDialog->AddEntries(newEntries);
			}
		);
		\endcode

		\param button Widget to add.
	*/
	void AddContextButton(QWidget* button);

	void AddContextMenuItem(QString title, const std::function<void(EntryItem item)>action);

	void SelectFirstValidEntry();

public slots:
	virtual void selectionChanged(size_t idx);
	void accept() override;
	void reject() override;
};
