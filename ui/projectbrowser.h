#pragma once

#include <QtWidgets/QLabel>
#include <QtGui/QStandardItemModel>
#include <qabstractitemmodel.h>
#include <qboxlayout.h>
#include <qfileiconprovider.h>
#include <qfilesystemwatcher.h>
#include <qlineedit.h>
#include <qmimedatabase.h>
#include <qnamespace.h>
#include <qplaintextedit.h>
#include <qsettings.h>
#include <qsortfilterproxymodel.h>
#include <qstandarditemmodel.h>
#include <qstyleditemdelegate.h>
#include <qtextbrowser.h>
#include <qtmetamacros.h>
#include <qtoolbutton.h>
#include <qtreeview.h>
#include <qlistwidget.h>
#include <qwidget.h>
#include <qpushbutton.h>
#include <globalarea.h>
#include <tabwidget.h>
#include <unordered_map>

#include "binaryninjaapi.h"
#include "clickablelabel.h"
#include "filter.h"
#include "menus.h"
#include "uitypes.h"


class BINARYNINJAUIAPI ProjectStatusWidget: public MenuHelper
{
protected:
	virtual void showMenu() override;
public:
	ProjectStatusWidget(QWidget* parent, const QString& text);
};


class BINARYNINJAUIAPI ProjectItemModel: public QStandardItemModel, public BinaryNinja::ProjectNotification
{
	Q_OBJECT

	ProjectRef m_project;

	QMimeDatabase m_mimeDatabase;
	QFileIconProvider m_iconProvider;
	QSettings m_qsettings;
	QLocale m_locale;

	QFileSystemWatcher* m_fsWatcher;

	std::unordered_map<std::string, QPersistentModelIndex> m_idIndexMap;

	QHash<QString, QString> m_pathMimeTypeCache;
	QHash<QString, size_t> m_pathSizeCache;
	QHash<QString, QIcon> m_pathIconCache;
	QHash<QString, int64_t> m_idUploadProgress;

	bool OnBeforeProjectMetadataWritten(BinaryNinja::Project*, std::string& key, BinaryNinja::Metadata* value) override;
	void OnAfterProjectFileCreated(BinaryNinja::Project*, BinaryNinja::ProjectFile*) override;
	void OnAfterProjectFileUpdated(BinaryNinja::Project*, BinaryNinja::ProjectFile*) override;
	void OnAfterProjectFileDeleted(BinaryNinja::Project*, BinaryNinja::ProjectFile*) override;
	void OnAfterProjectFolderCreated(BinaryNinja::Project*, BinaryNinja::ProjectFolder*) override;
	void OnAfterProjectFolderUpdated(BinaryNinja::Project*, BinaryNinja::ProjectFolder*) override;
	void OnAfterProjectFolderDeleted(BinaryNinja::Project*, BinaryNinja::ProjectFolder*) override;

	void AddFolder(ProjectFolderRef folder);
	void UpdateFolder(ProjectFolderRef folder);
	void RemoveFolder(ProjectFolderRef folder);

	void AddFile(ProjectFileRef file);
	void UpdateFile(ProjectFileRef file);
	void RemoveFile(ProjectFileRef file);

	void CachePathInformation(const QString& path);
	void RemoveCachedPathInformation(const QString& path);
	void WatchEvent(const QString& path);

public:
	ProjectItemModel(ProjectRef project, QObject* parent = nullptr);
	~ProjectItemModel();

	QStandardItem* ItemForId(const std::string& id);

	void reloadData(const std::function<bool(size_t, size_t)>& progress = [](size_t, size_t){ return true; });

	virtual QMimeData* mimeData(const QModelIndexList& indexes) const override;
	virtual bool dropMimeData(const QMimeData* data, Qt::DropAction action, int row, int column, const QModelIndex& parent) override;
	virtual bool canDropMimeData(const QMimeData *data, Qt::DropAction action, int row, int column, const QModelIndex &parent) const override;

	QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
	virtual bool setData(const QModelIndex& index, const QVariant& value, int role = Qt::EditRole) override;

	enum {
		TypeRole = Qt::UserRole,
		IdRole,
		DiskPathRole,
		SortRole,
	};

	enum {
		FileType,
		FolderType,
	};

	enum {
		COL_NAME = 0,
		COL_TYPE,
		COL_SIZE_ON_DISK,
		COL_CREATED,
		COL_LAST_OPENED,
		COL_STATUS,
		COLUMN_COUNT,
	};

Q_SIGNALS:
	void itemsDropped(Qt::DropAction action, const QList<QString> fileIds, const QList<QString> folderIds, const QList<QUrl> newUrls, ProjectFolderRef newParentFolder);

	void projectFileCreated(ProjectFileRef projectFile);
	void projectFileUpdated(ProjectFileRef projectFile);
	void projectFileDeleted(ProjectFileRef projectFile);

	void projectFolderCreated(ProjectFolderRef projectFolder);
	void projectFolderUpdated(ProjectFolderRef projectFolder);
	void projectFolderDeleted(ProjectFolderRef projectFolder);

private Q_SLOTS:
	void fileChanged(const QString& path);
	void directoryChanged(const QString& path);
};


class BINARYNINJAUIAPI SortFilterProjectItemModel: public QSortFilterProxyModel
{
	bool m_acceptAllFolders = false;

	ProjectRef m_project;

protected:
	virtual bool lessThan(const QModelIndex& sourceLeft, const QModelIndex& sourceRight) const override;
	virtual bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;

public:
	SortFilterProjectItemModel(ProjectRef project, QObject* parent = nullptr): QSortFilterProxyModel(parent), m_project(project) {};

	void setAcceptAllFolders(bool accept) { m_acceptAllFolders = accept; }
	bool acceptAllFolders() const { return m_acceptAllFolders; }
};


class BINARYNINJAUIAPI ProjectTreeStyle: public QProxyStyle
{
public:
	ProjectTreeStyle(QStyle* style) : QProxyStyle(style) {};

	void drawPrimitive(PrimitiveElement element, const QStyleOption* option, QPainter* painter, const QWidget* widget = nullptr) const override;
};


class BINARYNINJAUIAPI ProjectTree: public QTreeView, public FilterTarget
{
	Q_OBJECT

	QSet<QString> m_expandedIds;

	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void selectFirstItem() override;
	virtual void activateFirstItem() override;
	virtual void setFilter(const std::string& filter) override;

protected:
	void mousePressEvent(QMouseEvent* event) override;
	void keyPressEvent(QKeyEvent* event) override;
	void rowsInserted(const QModelIndex& parent, int start, int end) override;

public:
	ProjectTree(QWidget* parent = nullptr);

Q_SIGNALS:
	void filterChanged(const QString& filter);
};


class BINARYNINJAUIAPI RecentsList: public QListWidget, public FilterTarget
{
	Q_OBJECT

	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void selectFirstItem() override;
	virtual void activateFirstItem() override;
	virtual void setFilter(const std::string& filter) override;

public:

	enum {
		FileIdRole = Qt::UserRole,
		NameRole,
		PathRole
	};

	RecentsList(QWidget* parent = nullptr) : QListWidget(parent) {}
};


class BINARYNINJAUIAPI RecentFileItem: public QWidget
{
	Q_OBJECT

	ProjectFileRef m_projectFile;

	QIcon m_icon;
	QLabel* m_fileNameLabel;
	QLabel* m_filePathLabel;

public:
	RecentFileItem(ProjectFileRef file, QWidget* parent = nullptr);

Q_SIGNALS:
	void showInProject(ProjectFileRef file);
};


class BINARYNINJAUIAPI InfoWidget: public QWidget
{
	std::unordered_map<std::string, ProjectFileRef> m_files;
	std::unordered_map<std::string, ProjectFolderRef> m_folders;

	QVBoxLayout* m_layout;
	QLabel* m_descriptionTitleLabel;
	QTextEdit* m_descriptionText;
	QLabel* m_selectedItemNameLabel;
	QLabel* m_selectedItemDetailsLabel;

	QHBoxLayout* m_descriptionButtonLayout;
	QWidget* m_descriptionButtonWidget;
	QPushButton* m_descriptionSaveButton;
	QPushButton* m_descriptionCancelButton;

	bool HasDescriptionChanged() const;

	void descriptionChanged();
	void cancelChangeDescription();
	void saveDescription();

public:
	InfoWidget(QWidget* parent = nullptr);

	bool ContainsFile(const std::string& id);
	bool ContainsFolder(const std::string& id);

	void UpdateInfo();

	void PromptSave();

	void AddFile(ProjectFileRef file);
	void RemoveFile(ProjectFileRef file);

	void AddFolder(ProjectFolderRef folder);
	void RemoveFolder(ProjectFolderRef folder);
};


class BINARYNINJAUIAPI ProjectBrowser: public QWidget, public UIContextNotification, public BinaryNinja::ProjectNotification
{
	Q_OBJECT

	ProjectRef m_project;

	FilterEdit* m_projectFilterEdit;
	FilteredView* m_filteredTreeView;

	FilterEdit* m_recentsFilterEdit;
	FilteredView* m_filteredRecentsView;

	DockableTabBar* m_tabBar;

	ProjectItemModel* m_projectModel;
	SortFilterProjectItemModel* m_sortFilterProjectModel;
	QLabel* m_nameLabel;
	QLabel* m_descriptionLabel;
	ProjectTree* m_projectTree;
	InfoWidget* m_infoWidget;
	QWidget* m_projectContainer;

	RecentsList* m_recentFilesList;

	ClickableIcon* m_refreshButton;
	ClickableIcon* m_editDetailsButton;

	UIActionHandler m_projectActionHandler;
	ContextMenuManager* m_projectContextMenuManager = nullptr;
	Menu m_projectMenu;

	ProjectFolderRef GetFolderContainingIndex(const QModelIndex& index) const;
	QModelIndex GetCurrentSelectedIndex() const;

	virtual void OnAfterOpenProjectFile(UIContext* context, ProjectFileRef projectFile, ViewFrame* frame) override;

	void updateWindowTitle();
	void updateRecentFileList();
	void AddRecentProjectFile(ProjectFileRef projectFile);

	void UpdateDetails();
	void LoadProjectData();

	virtual void OnAfterProjectMetadataWritten(BinaryNinja::Project* project, std::string& key, BinaryNinja::Metadata* value) override;

	void storeTreeState();
	void restoreTreeState();

	void initActions();

private slots:
	void itemDoubleClicked(const QModelIndex& index);
	void openProjectFile(ProjectFileRef file, bool openWithOptions = false);
	void itemSelectionChanged(const QItemSelection& selected, const QItemSelection& deselected);
	void itemChanged(QStandardItem* item);
	void handleItemsDropped(Qt::DropAction action, const QList<QString> fileIds, const QList<QString> folderIds, const QList<QUrl> newUrls, ProjectFolderRef newParentFolder);
	void onTreeFilterChanged(const QString& filter);

protected:
	void SelectItems(std::vector<ProjectFileRef> files, std::vector<ProjectFolderRef> folders);
	void SelectItemsById(std::vector<std::string> fileIds, std::vector<std::string> folderIds);
	void PromptImportFile(ProjectFolderRef folder = nullptr);
	void PromptImportFolder(ProjectFolderRef parent = nullptr);
	void MakeNewFolder(ProjectFolderRef parent = nullptr);
	void PromptDeleteSelected();
	void PromptOpenSelected(bool withOptions = false);
	void PromptExportSelected();
	void PromptAnalyzeSelected();
	void PromptEditProjectDetails();
	void Refresh();

public:
	ProjectBrowser(QWidget* parent, ProjectRef project);
	~ProjectBrowser();

	ProjectRef GetProject() const { return m_project; };

	static void registerActions();
};
