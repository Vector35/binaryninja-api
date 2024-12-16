#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtCore/QItemSelectionModel>
#include <QtWidgets/QTableView>
#include <QtWidgets/QItemDelegate>
#include <QtWidgets/QDialog>
#include <QtWidgets/QComboBox>
#include "binaryninjaapi.h"
#include "viewframe.h"

#define TAGS_UPDATE_CHECK_INTERVAL 200

/*!

	\defgroup tagtypelist TagTypeList
 	\ingroup uiapi
*/

/*!

    \ingroup tagtypelist
*/
class BINARYNINJAUIAPI TagTypeListModel : public QAbstractItemModel, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

	QWidget* m_owner;
	BinaryViewRef m_data;
	std::vector<TagTypeRef> m_refs;
	std::map<std::string, uint64_t> m_count;

  public:
	TagTypeListModel(QWidget* parent, BinaryViewRef data);

	TagTypeRef& GetRef(int index) { return m_refs[index]; }
	const TagTypeRef& GetRef(int index) const { return m_refs[index]; }

	virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
	virtual QModelIndex parent(const QModelIndex& i) const override;
	virtual bool hasChildren(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent) const override;
	virtual int columnCount(const QModelIndex& parent) const override;
	virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
	virtual QVariant data(const QModelIndex& i, int role) const override;
	virtual bool setData(const QModelIndex& i, const QVariant& value, int role = Qt::EditRole) override;
	virtual void sort(int column, Qt::SortOrder order) override;
	virtual Qt::ItemFlags flags(const QModelIndex& i) const override;

	virtual void OnTagAdded(BinaryNinja::BinaryView*, const BinaryNinja::TagReference&) override;
	virtual void OnTagRemoved(BinaryNinja::BinaryView*, const BinaryNinja::TagReference&) override;

	bool setModelData(const std::vector<TagTypeRef>& refs, QItemSelectionModel* selectionModel, int sortColumn,
	    Qt::SortOrder sortOrder, bool& selectionUpdated);

  Q_SIGNALS:
	void needRepaint();
};

/*!

    \ingroup tagtypelist
*/
class BINARYNINJAUIAPI TagTypeItemDelegate : public QItemDelegate
{
	Q_OBJECT

	QFont m_font;
	QFont m_monospaceFont;
	QFont m_emojiFont;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;

	void initFont();

  public:
	TagTypeItemDelegate(QWidget* parent);

	void updateFonts();

	virtual QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	virtual void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	virtual void setEditorData(QWidget* editor, const QModelIndex& index) const override;
	virtual bool editorEvent(QEvent* event, QAbstractItemModel* model, const QStyleOptionViewItem& option,
	    const QModelIndex& index) override;
};

/*!

    \ingroup tagtypelist
*/
class BINARYNINJAUIAPI TagTypeList : public QTableView, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

	ViewFrame* m_view;
	TagTypeListModel* m_list;
	TagTypeItemDelegate* m_itemDelegate;
	BinaryViewRef m_data;
	UIActionHandler* m_handler;
	UIActionHandler m_actionHandler;
	ContextMenuManager* m_contextMenuManager;
	Menu* m_menu;

	QTimer* m_updateTimer;
	bool m_needsUpdate;
	bool m_needsRepaint;

  protected:
	virtual void contextMenuEvent(QContextMenuEvent* event) override;

	virtual void showEvent(QShowEvent* event) override;
	virtual void hideEvent(QHideEvent* event) override;

	virtual void OnTagTypeUpdated(BinaryNinja::BinaryView*, const TagTypeRef) override;

  private:
	void createTagType();
	void removeTagType();

  private Q_SLOTS:
	void updateTimerEvent();
	void needRepaint();

  public Q_SLOTS:
	void showContextMenu();

  public:
	TagTypeList(QWidget* parent, ViewFrame* view, BinaryViewRef data, Menu* menu = nullptr);
	virtual ~TagTypeList();
	void notifyFontChanged();

	static void registerActions();

	void updateData();
	bool hasSelection();
};

/*!

    \ingroup tagtypelist
*/
class BINARYNINJAUIAPI TagTypeDialogModel : public QAbstractItemModel
{
	Q_OBJECT

	QWidget* m_owner;
	BinaryViewRef m_data;
	std::vector<TagTypeRef> m_refs;

  public:
	TagTypeDialogModel(QWidget* parent, BinaryViewRef data);

	TagTypeRef& GetRef(int index) { return m_refs[index]; }
	const TagTypeRef& GetRef(int index) const { return m_refs[index]; }

	virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
	virtual QModelIndex parent(const QModelIndex& i) const override;
	virtual bool hasChildren(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent) const override;
	virtual int columnCount(const QModelIndex& parent) const override;
	virtual QVariant data(const QModelIndex& i, int role) const override;
};

/*!

    \ingroup tagtypelist
*/
class BINARYNINJAUIAPI TagTypeSelectDialog : public QDialog
{
	Q_OBJECT

	BinaryViewRef m_data;
	TagTypeDialogModel* m_model;
	QComboBox* m_tagTypeList;
	QLineEdit* m_tagTextInput;

  private Q_SLOTS:
	void select();

  public:
	TagTypeSelectDialog(QWidget* parent, BinaryViewRef data);

  Q_SIGNALS:
	void selected(TagTypeRef tagType, QString text);
};
