#pragma once

#include <QtWidgets/QAbstractScrollArea>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStyledItemDelegate>

#include "dockhandler.h"
#include "render.h"
#include "sidebar.h"
#include "uitypes.h"
#include "fontsettings.h"

/*!

	\defgroup memorymap MemoryMap
 	\ingroup uiapi
*/

/*!

    \ingroup memorymap
*/
class BINARYNINJAUIAPI DataComparedTableItem : public QTableWidgetItem
{
public:
	DataComparedTableItem(const QString& text, int type=QTableWidgetItem::ItemType::Type): QTableWidgetItem(text, type) {};
	bool operator<(const QTableWidgetItem& other) const;
};

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
	SectionDialog(QWidget* parent, BinaryViewRef data, SectionRef section = nullptr);
};

/*!

    \ingroup memorymap
*/
class BINARYNINJAUIAPI SegmentWidget : public QWidget, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

	enum SEGMENT_COLUMN {
		START = 0,
		END,
		DATA_OFFSET,
		DATA_LENGTH,
		FLAGS,
		COLUMN_COUNT,
	};

	BinaryViewRef m_data;
	QTableWidget* m_table;
	std::mutex m_updateMutex;

	void updateInfo();
	void showContextMenu(const QPoint& point);

	void addSegment();
	void editSegment(SegmentRef segment);
	void removeSegment(SegmentRef segment);

public:
	SegmentWidget(BinaryViewRef data);
	virtual ~SegmentWidget();

	void updateFont();
	void highlightRelatedSegments(SectionRef section);
	void itemChanged(QTableWidgetItem* current, QTableWidgetItem* previous);

	virtual void OnSegmentAdded(BinaryNinja::BinaryView* data, BinaryNinja::Segment* segment) override { updateInfo(); };
	virtual void OnSegmentUpdated(BinaryNinja::BinaryView* data, BinaryNinja::Segment* segment) override { updateInfo(); };
	virtual void OnSegmentRemoved(BinaryNinja::BinaryView* data, BinaryNinja::Segment* segment) override { updateInfo(); };

Q_SIGNALS:
	void currentSegmentChanged(SegmentRef current);
	void addressDoubleClicked(uint64_t address);
};

/*!

    \ingroup memorymap
*/
class BINARYNINJAUIAPI SectionWidget : public QWidget, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

	enum SECTION_COLUMN {
		NAME = 0,
		START,
		END,
		SEMANTICS,
		COLUMN_COUNT,
	};

	BinaryViewRef m_data;
	QTableWidget* m_table;
	std::mutex m_updateMutex;

	void updateInfo();
	void showContextMenu(const QPoint& point);

	void addSection();
	void editSection(SectionRef section);
	void removeSection(SectionRef section);

public:
	SectionWidget(BinaryViewRef data);
	virtual ~SectionWidget();

	void updateFont();
	void highlightRelatedSections(SegmentRef segment);
	void itemChanged(QTableWidgetItem* current, QTableWidgetItem* previous);

	virtual void OnSectionAdded(BinaryNinja::BinaryView* data, BinaryNinja::Section* section) override { updateInfo(); };
	virtual void OnSectionUpdated(BinaryNinja::BinaryView* data, BinaryNinja::Section* section) override { updateInfo(); };
	virtual void OnSectionRemoved(BinaryNinja::BinaryView* data, BinaryNinja::Section* section) override { updateInfo(); };

Q_SIGNALS:
	void currentSectionChanged(SectionRef current);
	void addressDoubleClicked(uint64_t address);
};

/*!

    \ingroup memorymap
*/
class BINARYNINJAUIAPI MemoryMapSidebarWidget : public SidebarWidget
{
	Q_OBJECT

	SectionWidget* m_sectionWidget;
	SegmentWidget* m_segmentWidget;
	QWidget* m_header;
	BinaryViewRef m_data;
	ViewFrame* m_frame;

	void navigateToAddress(uint64_t address);

  public:
	MemoryMapSidebarWidget(ViewFrame* view, BinaryViewRef data);

	void notifyFontChanged() override;
	QWidget* headerWidget() override { return m_header; }
};

/*!

    \ingroup memorymap
*/
class BINARYNINJAUIAPI MemoryMapSidebarWidgetType : public SidebarWidgetType
{
  public:
	MemoryMapSidebarWidgetType();
	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
};
