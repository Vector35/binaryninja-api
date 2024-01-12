#pragma once

#include <QtWidgets/QAbstractScrollArea>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QLineEdit>

#include "dockhandler.h"
#include "render.h"
#include "sidebar.h"
#include "uitypes.h"

#define STACK_VIEW_UPDATE_CHECK_INTERVAL 200

/*!

	\defgroup stackview StackView
 	\ingroup uiapi
*/

/*! Dialog to enable arbitrary stack variable creation.

    \ingroup stackview
*/
class BINARYNINJAUIAPI CreateStackVariableDialog : public QDialog
{
	Q_OBJECT

	BinaryViewRef m_data;
	FunctionRef m_func;

	QLineEdit* m_offsetField;
	QLineEdit* m_nameField;
	QComboBox* m_typeDropdown;

	//! Automatically update/sanitize the offset and name fields after input.
	void autoFillFields();

  protected:
	void accept() override;

  public:
	CreateStackVariableDialog(QWidget* parent, BinaryViewRef data, FunctionRef func, int64_t initialOffset = 0);
};

/*! A single line in the stack view.

    \ingroup stackview
*/
class StackViewLine
{
  public:
	enum class Type
	{
		Variable,
		Member,
		OffsetRef,
		Annotation,
		Fill
	};

	//! Create a new line for a variable.
	static StackViewLine variable(int64_t offset, const BinaryNinja::VariableNameAndType& vnat, PlatformRef plat);

	//! Create a new line for a struct or array member.
	static StackViewLine member(int64_t offset, const BinaryNinja::VariableNameAndType& vnat, PlatformRef plat);

	//! Create a new line for a struct offset reference.
	static StackViewLine offsetRef(int64_t base, uint64_t offset, size_t size);

	//! Create a new annotation line.
	static StackViewLine annotation(int64_t offset, const std::string& text);

	//! Create a new fill line.
	static StackViewLine fill(int64_t offset, size_t length);

	//! Get this line's type.
	StackViewLine::Type type() const;

	//! Get the stack frame offset for this line.
	int64_t offset() const;

	//! Get the number of bytes this line represents on the stack.
	size_t width() const;

	//! Get the hierarchical level of this line.
	size_t level() const;

	//! Set the hierarchical level for this line.
	void setLevel(size_t level);

	//! Get the type of the data this line represents.
	TypeRef dataType() const;

	//! Set the type of the data this line represents. Does not affect the underlying variable.
	void setDataType(TypeRef vnat);

	//! Get the variable represented by this line.
	BinaryNinja::Variable variable() const;

	//! Set the variable represented by this line.
	void setVariable(const BinaryNinja::Variable& var);

	//! Set a width override for this line.
	void setWidthOverride(size_t width);

	//! Is this line backed by data or is it ephermeral?
	bool isDataBacked() const;

	//! Is the data represented by this line referenced in the current function?
	bool isReferenced() const;

	//! Set whether the data represented by this line is referenced in the current function.
	void setIsReferenced(bool isReferenced);

	//! Is the data represented by this line unused in the current function?
	bool isUnused() const;

	//! Set whether the data represented by this line unused in the current function.
	void setIsUnused(bool isUnused);

	//! Get the content (with no offset) for this line.
	BinaryNinja::DisassemblyTextLine content() const;

	//! Get the content with the leading offset (or padding) for this line.
	BinaryNinja::DisassemblyTextLine contentWithOffset(bool hide = false) const;

	//! Get the width of the total line content in characters.
	size_t contentWidth(bool withOffset = true) const;

	//! Append a single token to this line's content.
	void appendToken(const BinaryNinja::InstructionTextToken& token);

	//! Append multiple tokens to this line's content.
	void appendTokens(const std::vector<BinaryNinja::InstructionTextToken>& tokens);

	//! Indent this line's content.
	void indent(size_t levels = 1);

  private:
	StackViewLine(StackViewLine::Type type, int64_t offset);

	StackViewLine::Type m_type;
	int64_t m_offset;
	size_t m_level;

	TypeRef m_dataType;
	BinaryNinja::Variable m_var;
	size_t m_widthOverride;

	bool m_isReferenced;
	bool m_isUnused;

	BinaryNinja::DisassemblyTextLine m_content;
};

/*! Simple direction enum; used for cursor movement functions.

    \ingroup stackview
*/
enum class Direction
{
	Up,
	Down,
	Left,
	Right
};

/*! The Stack View

    \ingroup stackview
*/
class BINARYNINJAUIAPI StackView : public QAbstractScrollArea, public View
{
	Q_OBJECT

	ViewFrame* m_view;
	BinaryViewRef m_data;
	FunctionRef m_func;
	BinaryNinja::AdvancedFunctionAnalysisDataRequestor m_analysisRequestor;
	RenderContext m_renderer;

	std::vector<StackViewLine> m_lines;
	HighlightTokenState m_highlight;
	size_t m_lineIndex;
	size_t m_tokenIndex;

	//! Bind and register all stack view actions.
	void setupActions();

	//! Internal refresh method, rebuilds all lines.
	void rebuildLines();

	//! Refresh the internal highlight token state.
	//!
	//! \param shouldUpdateStatus Should UIContext::updateStatus() be called?
	void refreshHighlight(bool shouldUpdateStatus = true);

	//! Find the end of a stack void given a start offset.
	int64_t findVoidEnd(int64_t start) const;

  protected:
	void paintEvent(QPaintEvent* event) override;
	void mousePressEvent(QMouseEvent* event) override;
	void mouseDoubleClickEvent(QMouseEvent* event) override;

  public:
	StackView(ViewFrame* view, BinaryViewRef data);

	//! Refresh the stack view's content.
	void refresh();

	//! Move the cursor to approximate clicked position.
	void moveCursorToMouse(QMouseEvent* event, bool isSelecting);

	//! Ensure the cursor is visible by adjusting the scroll position.
	void ensureCursorIsVisible();

	//! Move the cursor via the keyboard.
	void moveCursor(Direction dir);

	//! Ensure the cursor is not selecting any prohibited tokens.
	void sanitizeCursor(Direction preference);

	//! Get the selected StackViewLine.
	const StackViewLine* selectedLine() const;

	//! Rename the variable belonging to the selected line.
	void renameVariable();

	//! Change the type of the variable belonging to the selected line.
	void retypeVariable();

	//! Undefine the variable belonging to the selected line.
	void undefineVariable();

	//! Show the "Create Variable" dialog.
	void showCreateVariableDialog();

	//! Create an integer of the given size at the cursor position. Pass `0`
	//! for `size` to cycle through integer sizes automatically.
	void quickCreateIntegerAtCursor(size_t size);

	//! Toggle the sign of the integer at the cursor position.
	void quickInvertIntegerSignAtCursor();

	//! Create an float of the given size at the cursor position. Pass `0`
	//! for `size` to cycle through float sizes automatically.
	void quickCreateFloatAtCursor(size_t size);

	//! Create a pointer the cursor.
	void quickCreatePointerAtCursor();

	//! Create an array at the cursor, spanning until the next stack variable.
	void quickCreateArrayAtCursor();

	//! Create a new struct at the cursor, spanning until the next stack variable.
	void quickCreateStructAtCursor();

	//! Override the default event handler so we can have nice tooltips.
	bool event(QEvent* event) override;

	BinaryViewRef getData() override;
	uint64_t getCurrentOffset() override;
	bool canCopyAddress() override { return false; };
	bool canPaste() override { return false; };
	void setSelectionOffsets(BNAddressRange range) override;
	bool navigate(uint64_t offset) override;
	QFont getFont() override;
	void updateFonts() override;
};

/*! Stack view sidebar widget wrapper.

    \ingroup stackview
*/
class BINARYNINJAUIAPI StackViewSidebarWidget : public SidebarWidget
{
	Q_OBJECT

	StackView* m_stackView;

  public:
	StackViewSidebarWidget(ViewFrame* view, BinaryViewRef data);

	void refresh();
	void focus() override { refresh(); }
	void notifyFontChanged() override { m_stackView->updateFonts(); }
};

/*!

    \ingroup stackview
*/
class BINARYNINJAUIAPI StackViewSidebarWidgetType : public SidebarWidgetType
{
  public:
	StackViewSidebarWidgetType();
	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	virtual SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::RightContent; }
};
