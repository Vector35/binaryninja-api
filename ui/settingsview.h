#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtCore/QItemSelection>
#include <QtCore/QModelIndex>
#include <QtCore/QRegularExpression>
#include <QtCore/QSize>
#include <QtCore/QSortFilterProxyModel>
#include <QtCore/QTimer>
#include <QtCore/QVariant>
#include <QtGui/QMouseEvent>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QStyledItemDelegate>
#include <QtWidgets/QTreeView>

#include <map>
#include <optional>
#include <set>
#include <utility>
#include <vector>
#include "binaryninjaapi.h"
#include "json/json.h"
#include "render.h"
#include "menus.h"
#include "clickablelabel.h"


struct SettingsEntry
{
	SettingsEntry(int p, const QString& h, const QString& g, std::vector<void*>&& j) :
	    parent(p), heading(h), group(g), jsonDefs(j)
	{}
	int parent;
	QString heading;
	QString group;
	std::vector<void*> jsonDefs;
	std::vector<QString> subgroups;
};


class BINARYNINJAUIAPI SettingsTreeModel : public QAbstractItemModel
{
	Q_OBJECT

  private:
	Json::Value m_schema;
	std::vector<SettingsEntry> m_store;
	std::map<std::string, QString> m_filterText;

  public:
	SettingsTreeModel(std::string schema, QObject* parent = 0);
	~SettingsTreeModel();

	QVariant data(const QModelIndex& index, int role) const override;
	Qt::ItemFlags flags(const QModelIndex& index) const override;
	QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

	QModelIndex index(int row, int column, const QModelIndex& parent = QModelIndex()) const override;
	QModelIndex parent(const QModelIndex& index) const override;

	int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	int columnCount(const QModelIndex& parent = QModelIndex()) const override;

	bool setData(const QModelIndex& index, const QVariant& value, int role = Qt::EditRole) override;

	void updateModel();
};


class BINARYNINJAUIAPI SettingsFilterProxyModel : public QSortFilterProxyModel
{
	Q_OBJECT

	int m_scopeFilter = SettingsAutoScope;
	std::map<std::string, int> m_itemScope;
	mutable QRegularExpression m_regExp;
	mutable std::map<QString, std::set<QString>> m_subgroupFilterCache;

  public:
	SettingsFilterProxyModel(QObject* parent = 0);

	int scopeFilter() { return m_scopeFilter; }
	void setScopeFilter(int scope)
	{
		m_scopeFilter = scope;
		invalidateFilter();
		m_subgroupFilterCache.clear();
	}

	QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;

  protected:
	bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;
	bool lessThan(const QModelIndex& left, const QModelIndex& right) const override;

  public Q_SLOTS:
	void updateScope(const std::string& key, int scope) { m_itemScope[key] = scope; }
};


class BINARYNINJAUIAPI SettingsOutlineProxyModel : public QSortFilterProxyModel
{
	Q_OBJECT

  public:
	SettingsOutlineProxyModel(QObject* parent = 0);

  protected:
	bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;
};


class BINARYNINJAUIAPI SettingsEditor : public QWidget
{
	Q_OBJECT

  private:
	SettingsRef m_settings;
	Json::Value m_setting;
	std::string m_settingKey;
	BinaryViewRef m_view = nullptr;
	BNSettingsScope m_scope = SettingsAutoScope;

	QLabel* m_title = nullptr;
	ClickableLabel* m_description = nullptr;
	QLabel* m_settingKeyText = nullptr;
	QLabel* m_settingSep = nullptr;
	QLabel* m_message = nullptr;

	BNSettingsScope m_currSettingScope = SettingsDefaultScope;
	QLabel* m_scopeText = nullptr;
	QCheckBox* m_checkBox = nullptr;
	QLineEdit* m_settingText = nullptr;
	QDoubleSpinBox* m_doubleSpinBox = nullptr;
	QSpinBox* m_spinBox = nullptr;
	QComboBox* m_comboBox = nullptr;
	QLineEdit* m_arrayText = nullptr;
	std::set<QString> m_validComboSelections;
	Json::StreamWriterBuilder m_builder;

	bool m_optional = false;
	bool m_readOnly = false;
	bool m_requiresRestart = false;
	bool m_settingModified = false;

  public:
	SettingsEditor(
	    QWidget* parent, SettingsRef settings, BinaryViewRef view, BNSettingsScope scope, const Json::Value* setting);
	~SettingsEditor();

	QSize sizeHint() const override;
	void setSetting(const Json::Value* value, bool updateSchema = false);

  Q_SIGNALS:
	void geometryChanged();
	void settingChanged();
	void allSettingsChanged();
	void showIdentifiers(bool enable);
	void notifyScope(const std::string& key, int scope);
	void notifySettingChanged(QString);
	void notifyNeedsRestart();

  private:
	void notifySettingUpdate();  // TODO core notification callbacks

  private Q_SLOTS:
	void toggleBoolSetting();
	void updateBoolSetting(bool enabled);
	void updateEnumStringSetting(const QString& text);
	void updateStringSetting();
	void updateFormatedNumberSetting();
	void updateDoubleNumberSetting(double value);
	void updateIntNumberSetting(int value);
	void updateArraySetting();
	void addArrayStringSetting(const QString& text);
	void resetSetting();
	void resetAllSettings(BNSettingsScope scope);

	// TODO GUI plugins
	void selectFont();
	void selectUiFont();
	void selectInterpreter();
	void selectVirtualEnv();

  public Q_SLOTS:
	void updateScope(BinaryViewRef, BNSettingsScope);
	void updateSize();
	void updateViewMode(bool enabled);

  private:
	void contextMenu();

  protected:
	bool eventFilter(QObject* obj, QEvent* event) override;
	void mousePressEvent(QMouseEvent* event) override;
	void paintEvent(QPaintEvent* event) override;
};


class BINARYNINJAUIAPI SettingsDelegate : public QStyledItemDelegate
{
	Q_OBJECT

  private:
	SettingsRef m_settings;
	SettingsFilterProxyModel* m_filterModel;
	BinaryViewRef m_view = nullptr;
	BNSettingsScope m_scope = SettingsAutoScope;
	QFont m_groupFont;
	QFont m_subgroupFont;
	QFont m_monoFont;
	int m_monoFontHeight;
	QTimer* m_updateModelTimer;

	QTreeView* m_treeView;
	std::function<void(const QModelIndex& index)> m_hoverAction = nullptr;
	std::function<void()> m_defaultSelectionAction = nullptr;

  public:
	SettingsDelegate(QWidget* parent, SettingsRef settings, SettingsFilterProxyModel* filterModel,
	    const std::function<void(const QModelIndex& index)>& hoverAction = nullptr);
	~SettingsDelegate();

	void setDefaultSelection(const std::function<void()>& selectionAction);

	void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override;

	QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const override;

	QWidget* createEditor(QWidget* parent, const QStyleOptionViewItem& option, const QModelIndex& index) const override;
	void setEditorData(QWidget* editor, const QModelIndex& index) const override;
	void setModelData(QWidget* editor, QAbstractItemModel* model, const QModelIndex& index) const override;
	void updateEditorGeometry(QWidget* editor, const QStyleOptionViewItem& option, const QModelIndex& index) const override;

  protected:
	bool eventFilter(QObject* object, QEvent* event) override;

  public:
  Q_SIGNALS:
	void refreshAllSettings() const;
	void scopeChanged(BinaryViewRef, BNSettingsScope);
	void sizeChanged();
	void viewModeChanged(bool enabled) const;
	void notifyNeedsRestart() const;
	void notifySettingChanged(QString settingId) const;
	void performHoverAction(QModelIndex index) const;

  public Q_SLOTS:
	void updateFonts();
	void updateModel();
	void updateScope(BinaryViewRef, BNSettingsScope);
	void updateSize();
	void updateViewMode(bool enabled) const;

  private Q_SLOTS:
	void commitEditorData();
	void editorGeometryChanged();
};


class BINARYNINJAUIAPI SettingsTreeView : public QTreeView
{
	Q_OBJECT

  public:
	explicit SettingsTreeView(QWidget* parent);
	~SettingsTreeView();

  protected:
	virtual void resizeEvent(QResizeEvent* event) override;


  public Q_SLOTS:
	void modelChanged(const QModelIndex& topLeft, const QModelIndex& bottomRight);
};


class BINARYNINJAUIAPI BinaryViewScopeLabel : public MenuHelper
{
	Q_OBJECT

	BNSettingsScope m_scope;
	QString m_scopeName;
	std::vector<QString> m_actionNames;
	std::vector<std::pair<BinaryViewRef, QString>> m_views;
	QString m_curName;
	BinaryViewRef m_curView = nullptr;

	UIActionHandler m_actionHandler;

  public:
	BinaryViewScopeLabel(QWidget* parent, const QString& name = "", BNSettingsScope scope = SettingsAutoScope);

	void refresh();
	const QString& currentSelection() { return m_curName; }
	BinaryViewRef currentBinaryView() { return m_curView; }

  Q_SIGNALS:
	void itemSelected(BinaryViewRef, BNSettingsScope);

  protected:
	virtual void showEvent(QShowEvent* event) override;
	virtual void showMenu() override;
};


class BINARYNINJAUIAPI SettingsScopeBar : public QWidget
{
	Q_OBJECT

	QPushButton* m_userLabel;
	BinaryViewScopeLabel* m_projectLabel;
	BinaryViewScopeLabel* m_resourceLabel;
	ClickableLabel* m_openProjectLabel;
	QLabel* m_desc;
	unsigned long m_highlightIdx;

	void setScopeHighlight(unsigned long highlightIdx);

  public:
	SettingsScopeBar(QWidget* parent = nullptr);

	void refresh();
	void updateTheme();

  Q_SIGNALS:
	void scopeChanged(BinaryViewRef, BNSettingsScope);
};


class BINARYNINJAUIAPI SearchFilter : public QLineEdit
{
	Q_OBJECT

	std::map<QString, int> m_filterTags;
	QRegularExpression m_regexTagExtract;
	QTimer* m_filterDelayTimer = nullptr;
	int m_delay;

  public:
	SearchFilter(QWidget* parent = nullptr);

	void addTag(const QString& tagName, int tag);
	void setDelay(int msec = 100) { m_delay = msec; }
	void setFilter();

	std::pair<QString, std::vector<int>> getSearchParams();

  protected:
	void keyPressEvent(QKeyEvent* event) override;

  Q_SIGNALS:
	void delayedTextChanged();
};


class BINARYNINJAUIAPI SettingsView : public QWidget
{
	Q_OBJECT

  private:
	QWidget* m_owner = nullptr;
	SettingsRef m_settings;
	SettingsFilterProxyModel* m_proxyModel = nullptr;
	SettingsOutlineProxyModel* m_outlineProxyModel = nullptr;
	QTreeView* m_outlineView = nullptr;
	SettingsTreeView* m_settingsTreeView = nullptr;
	SettingsDelegate* m_delegate = nullptr;
	SettingsScopeBar* m_scopeBar = nullptr;
	QCheckBox* m_viewMode = nullptr;
	SearchFilter* m_search = nullptr;
	bool m_outlineNavEnabled = true;

  public:
	SettingsView(QWidget* parent);
	SettingsView(QWidget* parent, SettingsRef settings);
	~SettingsView();

	SettingsRef getSettings() { return m_settings; }

	void init(std::string schema, bool uiScopeSelection);
	void refreshAllSettings();
	void refreshCurrentScope();
	void setData(BinaryViewRef view, const QString& name = "");
	void setDefaultGroupSelection(const QString& group);
	void focusSearch();

  public Q_SLOTS:
	void updateFonts();
	void updateTheme();

  private Q_SLOTS:
	void outlineSelectionChanged(const QItemSelection& selected, const QItemSelection& deselected);
	void updateScopeFilter();
	void updateTextFilter();

  Q_SIGNALS:
	void fontsChanged();
	void notifyNeedsRestart();
	void notifySettingChanged(QString settingId) const;
};
