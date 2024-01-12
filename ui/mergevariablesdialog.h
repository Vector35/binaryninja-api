#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QListWidgetItem>
#include <QtWidgets/QStyledItemDelegate>

#include <string>
#include "binaryninjaapi.h"
#include "uicontext.h"
#include "render.h"

/*!

	\defgroup mergevariablesdialog
 	\ingroup uiapi
*/

/*!

    \ingroup mergevariablesdialog
*/
class BINARYNINJAUIAPI MergeVariableHeader : public QWidget
{
	std::vector<BinaryNinja::InstructionTextToken> m_tokens;
	RenderContext m_renderContext;
	int m_length;

protected:
	void paintEvent(QPaintEvent* event) override;
	QSize sizeHint() const override;

public:
	MergeVariableHeader(const std::vector<BinaryNinja::InstructionTextToken>& tokens, QWidget* parent = nullptr);
};

/*!

    \ingroup mergevariablesdialog
*/
class BINARYNINJAUIAPI MergeVariableListItem : public QListWidgetItem
{
	QWidget* m_owner;
	FunctionRef m_func;
	BinaryNinja::Variable m_var;
	std::string m_name;
	BinaryNinja::Confidence<BinaryNinja::Ref<BinaryNinja::Type>> m_type;
	bool m_grayed;

public:
	MergeVariableListItem(QWidget* parent, BinaryNinja::Function* func, const BinaryNinja::Variable& var,
		const std::string& name, BinaryNinja::Confidence<BinaryNinja::Ref<BinaryNinja::Type>> type,
		const QString& warnings, bool grayed);
	const BinaryNinja::Variable& variable() const { return m_var; }
	virtual QVariant data(int role) const override;

	static std::vector<BinaryNinja::InstructionTextToken> tokensForVariable(BinaryNinja::Function* func,
		const BinaryNinja::Variable& var, BinaryNinja::Confidence<BinaryNinja::Ref<BinaryNinja::Type>> type,
		const std::string& name);
};

/*!

    \ingroup mergevariablesdialog
*/
class BINARYNINJAUIAPI MergeVariableItemDelegate : public QStyledItemDelegate
{
	Q_OBJECT

	QWidget* m_parent;
	QFont m_font;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;

public:
	MergeVariableItemDelegate(QWidget* parent);

	void updateFonts();
	virtual QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	virtual void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
};

/*!

    \ingroup mergevariablesdialog
*/
class BINARYNINJAUIAPI MergeVariablesDialog : public QDialog
{
	Q_OBJECT
	QListWidget* m_list;
	QLineEdit* m_searchBox;
	std::set<BinaryNinja::Variable> m_existingVariables;
private Q_SLOTS:
	void searchTextChanged(const QString& searchText);

public:
	MergeVariablesDialog(QWidget* parent, FunctionRef func, BinaryNinja::Variable target);

	std::set<BinaryNinja::Variable> mergedVariables();
	std::set<BinaryNinja::Variable> unmergedVariables();
};
