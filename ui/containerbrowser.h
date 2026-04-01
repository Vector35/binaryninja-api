#pragma once

#include <QDialog>
#include <QStringList>
#include <QLineEdit>
#include <QTreeView>
#include <QPlainTextEdit>
#include <QLabel>
#include <QDialogButtonBox>
#include <QModelIndex>
#include <QSplitter>

#include "binaryninjaapi.h"
#include "uitypes.h"

#include <vector>


class ContainerTreeModel : public QAbstractItemModel
{
	Q_OBJECT

	struct Node
	{
		QString displayName;          // GetFileName() (or synthesized for root)
		QString type;                 // GetTransformName() or "Leaf"/"Root"
		QString breadcrumb;           // human-readable path "a ▸ b ▸ c"
		QStringList pathSegments;     // list of filenames from root to this node
		QString size;
		TransformContextRef ctx;
		Node* parent = nullptr;
		std::vector<std::unique_ptr<Node>> children;
	};

	TransformSessionRef m_session;
	std::unique_ptr<Node> m_root;
	QLocale m_locale;

	const Node* nodeFromIndex(const QModelIndex& index) const;
	static QString joinBreadcrumb(const QStringList& segments);
	void createChildren(Node* parentNode, const std::vector<TransformContextRef>& children, const QStringList& parentSegments = {});

public:
	enum Columns { ColName, ColType, ColSize, ColPath, ColCount };

	ContainerTreeModel(TransformSessionRef session, QObject* parent = nullptr);

	int columnCount(const QModelIndex& parent = {}) const override;
	QModelIndex index(int row, int column, const QModelIndex& parent = {}) const override;
	QModelIndex parent(const QModelIndex& child) const override;
	int rowCount(const QModelIndex& parent = {}) const override;
	QVariant data(const QModelIndex& index, int role) const override;
	QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
	Qt::ItemFlags flags(const QModelIndex& index) const override;

	QString getDisplayName(const QModelIndex& index) const;
	TransformContextRef getTransformContext(const QModelIndex& index) const;

	QStringList pathFor(const QModelIndex& index) const;
	void selectNode(const QModelIndex& index);
	void rebuild();
};


class AllColumnsFilterProxyModel : public QSortFilterProxyModel
{
	Q_OBJECT

public:
	explicit AllColumnsFilterProxyModel(QObject* parent = nullptr);

protected:
	bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;
};


class BINARYNINJAUIAPI ContainerBrowser : public QDialog
{
	Q_OBJECT

	TransformSessionRef m_session;

	ContainerTreeModel* m_model;

	QLineEdit* m_filter = nullptr;
	QTreeView* m_tree = nullptr;
	QPlainTextEdit* m_preview = nullptr;
	QSplitter* m_splitter = nullptr;
	QLabel* m_status = nullptr;
	QLabel* m_extractionStatus = nullptr;
	QDialogButtonBox* m_buttons = nullptr;
	AllColumnsFilterProxyModel* m_proxy = nullptr;

	QPushButton* m_openWithOptionsButton = nullptr;

	QStringList m_pendingSelectionPath;
	QStringList m_selectedPaths;
	int m_lastPreviewSize = 0;
	int m_dialogWidth = 0;
	bool m_openWithOptionsRequested = false;

	void connectSignals();
	void updatePreviewForIndex(const QModelIndex& proxyIndex);
	bool requiresPassword(TransformContextRef context);
	bool requiresExtraction(TransformContextRef context);
	void extractItem(TransformContextRef context);
	void promptForPassword(TransformContextRef context, bool tryCachedPassword = false);
	void showContextMenu(const QPoint& position);
	static QString toHexDump(const QByteArray& data, int bytesPerLine = 16);
	static QString formatMetadata(BinaryNinja::Ref<BinaryNinja::Metadata> metadata, int indent = 0);
	QModelIndex findNodeByPath(const QStringList& path);
	QModelIndex findFirstLeaf();
	QModelIndex findLeafByName(const QString& name);
	void selectNodeByPath(const QStringList& path);
	void selectLeafByName(const QString& name);

public:
	ContainerBrowser(TransformSessionRef session, QWidget* parent = nullptr);

	QStringList selectedPaths() const { return m_selectedPaths; }
	bool openWithOptionsRequested() const { return m_openWithOptionsRequested; }

	static std::vector<TransformContextRef> openContainerFile(const QString& path, bool forceShowDialog = false, bool* outOpenWithOptions = nullptr);
};
