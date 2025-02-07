#pragma once

#include <QtWidgets/QAbstractScrollArea>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStyledItemDelegate>
#include <QtCore/QSortFilterProxyModel>

#include "render.h"
#include "sidebar.h"
#include "uitypes.h"
#include "fontsettings.h"
#include "viewframe.h"

/*!

	\defgroup memorymap MemoryMap
 	\ingroup uiapi
*/

/*!

    \ingroup memorymap
*/
class BINARYNINJAUIAPI MemoryMapItemDelegate : public QStyledItemDelegate
{
public:
	MemoryMapItemDelegate(QObject* parent = nullptr): QStyledItemDelegate(parent) {};
	virtual void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override;
};

/*!

    \ingroup memorymap
*/
class BINARYNINJAUIAPI SegmentDialog : public QDialog
{

	QPushButton* m_acceptButton;
	QPushButton* m_cancelButton;
	QLineEdit* m_startField;
	QLineEdit* m_lengthField;
	QLineEdit* m_dataOffsetField;
	QLineEdit* m_dataLengthField;
	QCheckBox* m_flagRead;
	QCheckBox* m_flagWrite;
	QCheckBox* m_flagExec;

	BinaryViewRef m_data;
	SegmentRef m_segment;

	void Submit();
public:
	SegmentDialog(QWidget* parent, BinaryViewRef data, SegmentRef segment = nullptr);
};

/*!

    \ingroup memorymap
*/
class BINARYNINJAUIAPI SectionDialog : public QDialog
{

	QPushButton* m_acceptButton;
	QPushButton* m_cancelButton;
	QLineEdit* m_nameField;
	QLineEdit* m_startField;
	QLineEdit* m_lengthField;
	QComboBox* m_semanticsField;

	BinaryViewRef m_data;
	SectionRef m_section;

	void Submit();
public:
	void SetDefaultValues(const QString& name, uint64_t start, uint64_t length, BNSectionSemantics semantics);
	SectionDialog(QWidget* parent, BinaryViewRef data, SectionRef section = nullptr);
};


enum class SegmentColumn : int {
	START = 0,
	END,
	DATA_OFFSET,
	DATA_LENGTH,
	FLAGS,
	COLUMN_COUNT,
};


class BINARYNINJAUIAPI SegmentModel : public QAbstractItemModel, public BinaryNinja::BinaryDataNotification
{
	BinaryViewRef m_data;

	std::vector<SegmentRef> m_segments;

	QHash<QPersistentModelIndex, bool> m_highlightedIndices;

public:
	SegmentModel(BinaryViewRef data, QObject* parent = nullptr);
	~SegmentModel();

	int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	int rowCount(const QModelIndex& parent = QModelIndex()) const override;

	QModelIndex index(int row, int column, const QModelIndex& parent = QModelIndex()) const override;
	QModelIndex parent(const QModelIndex& child) const override;
	bool hasChildren(const QModelIndex&) const override;

	QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
	bool setData(const QModelIndex& index, const QVariant& value, int role = Qt::EditRole) override;

	QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

	virtual void OnSegmentAdded(BinaryNinja::BinaryView* data, BinaryNinja::Segment* segment) override;
	virtual void OnSegmentUpdated(BinaryNinja::BinaryView* data, BinaryNinja::Segment* segment) override;
	virtual void OnSegmentRemoved(BinaryNinja::BinaryView* data, BinaryNinja::Segment* segment) override;
};

/*!

    \ingroup memorymap
*/
class BINARYNINJAUIAPI SegmentWidget : public QWidget
{
	Q_OBJECT

	BinaryViewRef m_data;
	QTableView* m_table;
	SegmentModel* m_model;
	QSortFilterProxyModel* m_proxyModel;
	std::mutex m_updateMutex;

	//void updateInfo();
	void showContextMenu(const QPoint& point);

	void addSegment();
	void editSegment(SegmentRef segment);
	void removeSegment(SegmentRef segment);

public:
	SegmentWidget(BinaryViewRef data, QWidget* parent = nullptr);
	virtual ~SegmentWidget();

	void updateFont();
	void highlightRelatedSegments(SectionRef section);
	void currentRowChanged(const QModelIndex& current, const QModelIndex& previous);

Q_SIGNALS:
	void currentSegmentChanged(SegmentRef current);
	void addressDoubleClicked(uint64_t address);
	void rawAddressDoubleClicked(uint64_t address);
};


enum class SectionColumn: int
{
	NAME = 0,
	START,
	END,
	SEMANTICS,
	COLUMN_COUNT,
};


class BINARYNINJAUIAPI SectionModel : public QAbstractItemModel, public BinaryNinja::BinaryDataNotification
{
	BinaryViewRef m_data;

	std::vector<SectionRef> m_sections;

	QHash<QPersistentModelIndex, bool> m_highlightedIndices;

public:
	SectionModel(BinaryViewRef data, QObject* parent = nullptr);
	~SectionModel();

	int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	int rowCount(const QModelIndex& parent = QModelIndex()) const override;

	QModelIndex index(int row, int column, const QModelIndex& parent = QModelIndex()) const override;
	QModelIndex parent(const QModelIndex& child) const override;
	bool hasChildren(const QModelIndex&) const override;

	QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
	bool setData(const QModelIndex& index, const QVariant& value, int role = Qt::EditRole) override;

	QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

	virtual void OnSectionAdded(BinaryNinja::BinaryView* data, BinaryNinja::Section* section) override;
	virtual void OnSectionUpdated(BinaryNinja::BinaryView* data, BinaryNinja::Section* section) override;
	virtual void OnSectionRemoved(BinaryNinja::BinaryView* data, BinaryNinja::Section* section) override;
};

/*!

    \ingroup memorymap
*/
class BINARYNINJAUIAPI SectionWidget : public QWidget
{
	Q_OBJECT

	BinaryViewRef m_data;
	QTableView* m_table;
	SectionModel* m_model;
	QSortFilterProxyModel* m_proxyModel;
	std::mutex m_updateMutex;

	void showContextMenu(const QPoint& point);

	void addSection();
	void editSection(SectionRef section);
	void removeSection(SectionRef section);

public:
	SectionWidget(BinaryViewRef data, QWidget* parent = nullptr);
	virtual ~SectionWidget();

	void updateFont();
	void highlightRelatedSections(SegmentRef segment);
	void currentRowChanged(const QModelIndex& current, const QModelIndex& previous);

Q_SIGNALS:
	void currentSectionChanged(SectionRef current);
	void addressDoubleClicked(uint64_t address);
};

// I hate C++
class MemoryMapContainer;
class MemoryMapSidebarWidget;

/*!

    \ingroup memorymap
*/
class BINARYNINJAUIAPI MemoryMapView : public QWidget, public View
{
	Q_OBJECT

	BinaryViewRef m_data;
	MemoryMapContainer* m_container;

	SectionWidget* m_sectionWidget;
	SegmentWidget* m_segmentWidget;

	uint64_t m_currentOffset;

	void navigateToAddress(uint64_t address);
	void navigateToRawAddress(uint64_t address);

public:
	MemoryMapView(BinaryViewRef data, MemoryMapContainer* container);

	BinaryViewRef getData() override { return m_data; }
	uint64_t getCurrentOffset() override;
	BNAddressRange getSelectionOffsets() override;
	void setSelectionOffsets(BNAddressRange range) override;
	bool navigate(uint64_t offset) override;
	QFont getFont() override { return getMonospaceFont(this); }

	void setCurrentOffset(uint64_t offset);

	void updateFonts() override;
};

/*!

    \ingroup memorymap
*/
class BINARYNINJAUIAPI MemoryMapContainer : public QWidget, public ViewContainer
{
	Q_OBJECT

	friend class StringsView;

	MemoryMapView* m_memoryMap;
	MemoryMapSidebarWidget* m_widget;

public:
	MemoryMapContainer(BinaryViewRef data, MemoryMapSidebarWidget* parent);
	virtual View* getView() override { return m_memoryMap; }

	MemoryMapView* getMemoryMapView() { return m_memoryMap; }

protected:
	virtual void focusInEvent(QFocusEvent* event) override;
};

/*!

    \ingroup memorymap
*/
class MemoryMapViewType : public ViewType
{
	static MemoryMapViewType* m_instance;

public:
	MemoryMapViewType();
	virtual int getPriority(BinaryViewRef data, const QString& filename);
	virtual QWidget* create(BinaryViewRef data, ViewFrame* viewFrame);
	static void init();
};

/*!

    \ingroup memorymap
*/
class BINARYNINJAUIAPI MemoryMapSidebarWidget : public SidebarWidget
{
Q_OBJECT

	friend class MemoryMapView;

	MemoryMapContainer* m_container;

public:
	MemoryMapSidebarWidget(BinaryViewRef data);
	void focus() override;
};

/*!

    \ingroup memorymap
*/
class BINARYNINJAUIAPI MemoryMapSidebarWidgetType : public SidebarWidgetType
{
public:
	MemoryMapSidebarWidgetType();
	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::LeftContent; }
	SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }
	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	virtual bool canUseAsPane(SplitPaneWidget*, BinaryViewRef) const override { return true; }
	virtual Pane* createPane(SplitPaneWidget* panes, BinaryViewRef data) override;
};
