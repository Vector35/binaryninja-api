#pragma once

#include <QtWidgets/QWidget>
#include <QtWidgets/QDialog>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QLabel>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QListWidget>

struct TypeArchiveConflict
{
	BinaryNinja::Ref<BinaryNinja::TypeArchive> archive;
	std::string typeId;
	std::string baseSnapshotId;
	std::string firstSnapshotId;
	std::string secondSnapshotId;
	BinaryNinja::QualifiedName baseSnapshotName;
	BinaryNinja::QualifiedName firstSnapshotName;
	BinaryNinja::QualifiedName secondSnapshotName;
	TypeRef baseSnapshotType;
	TypeRef firstSnapshotType;
	TypeRef secondSnapshotType;
	std::function<bool(const std::string&)> success;
};


class TypeArchiveConflictDialog : public QDialog
{
	Q_OBJECT
	QWidget* m_parent;

	QListWidget* m_conflictList;
	QCheckBox* m_rawCheckBox;

	QLabel* m_baseLabel;
	QLabel* m_leftLabel;
	QLabel* m_rightLabel;

	QTextEdit* m_baseText;
	QTextEdit* m_leftText;
	QTextEdit* m_rightText;
	QLabel* m_titleLabel;

	std::unordered_map<std::string, TypeArchiveConflict> m_conflicts;

	std::string m_currentResolve;

public:
	TypeArchiveConflictDialog(QWidget* parent = nullptr);
	bool Handle(const std::vector<TypeArchiveConflict>& conflicts);

public Q_SLOTS:
	void UpdateDiffContents();

protected:
	void resizeEvent(QResizeEvent *) override;
	std::string typeToLines(const std::string& id, const BinaryNinja::QualifiedName& name, TypeRef type, const std::string& printer = "") const;
	QString conflictName(const std::string& id) const;
	QString trimLength(const QString& str, int width) const;

private Q_SLOTS:
	void UpdateConflictLabels();
	void UpdateConflictList();
	void AcceptFirst();
	void AcceptSecond();
	void AcceptAllFirst();
	void AcceptAllSecond();
};