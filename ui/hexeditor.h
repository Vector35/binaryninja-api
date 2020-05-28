#pragma once

#include <QtWidgets/QAbstractScrollArea>
#include <QtCore/QTimer>
#include "binaryninjaapi.h"
#include "viewframe.h"
#include "render.h"
#include "menus.h"
#include "statusbarwidget.h"
#include "uicontext.h"

#define HEX_EDITOR_UPDATE_CHECK_INTERVAL 200

class BINARYNINJAUIAPI HexEditor : public QAbstractScrollArea, public View, public PreviewScrollHandler,
	public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT
public:
	explicit HexEditor(BinaryViewRef data, ViewFrame* view, uint64_t startAddr = 0);
	virtual ~HexEditor();

	virtual bool canAssemble() override { return true; }
	virtual bool canCompile() override { return true; }

	virtual BinaryViewRef getData() override { return m_data; }
	virtual uint64_t getCurrentOffset() override;
	virtual BNAddressRange getSelectionOffsets() override;
	virtual bool navigate(uint64_t pos) override;

	virtual void OnBinaryDataWritten(BinaryNinja::BinaryView* data, uint64_t offset, size_t len) override;
	virtual void OnBinaryDataInserted(BinaryNinja::BinaryView* data, uint64_t offset, size_t len) override;
	virtual void OnBinaryDataRemoved(BinaryNinja::BinaryView* data, uint64_t offset, uint64_t len) override;

	virtual void writeData(const BinaryNinja::DataBuffer& data) override;
	virtual void selectAll();
	virtual void selectNone();

	void setSelectionRange(uint64_t begin, uint64_t end);

	virtual void updateFonts() override;

	virtual StatusBarWidget* getStatusBarWidget() override;

	virtual void followPointer();

	void setHighlightMode(HexEditorHighlightMode mode);
	void setColorMode(HexEditorColorMode mode);
	void setContrast(HexEditorHighlightContrast mode);

	virtual void sendWheelEvent(QWheelEvent* event) override;

	QFont getFont() override { return m_render.getFont(); }

	static void registerActions();

private:
	class HexEditorHighlightWidget: public MenuHelper
	{
	public:
		HexEditorHighlightWidget(HexEditor* parent);

	protected:
		virtual void showMenu();

	private:
		HexEditor* m_editor;
	};

	class HexEditorStatusBarWidget: public StatusBarWidget
	{
	public:
		HexEditorStatusBarWidget(HexEditor* parent);
		virtual void updateStatus() override;

	private:
		HexEditor* m_editor;
		HexEditorHighlightWidget* m_highlight;
	};

	struct HexEditorLine
	{
		bool separator;
		uint64_t addr;
		size_t len;
	};

	uint64_t getStart();
	uint64_t getEnd();
	uint64_t getLength();

	void updateRanges();

	void adjustSize(int width, int height);

	uint64_t getContiguousOffsetForAddress(uint64_t addr);
	uint64_t getAddressForContiguousOffset(uint64_t offset);

	void setTopToAddress(uint64_t addr);
	void refreshLines();
	void refreshAtCurrentLocation();
	bool cachePreviousLines();
	bool cacheNextLines();
	void updateCache();
	void scrollLines(int count);

	uint64_t getCursorPos();
	void setCursorPos(uint64_t pos);
	void repositionCaret();
	void updateCaret();
	void bindActions();

	std::pair<uint64_t, uint64_t> getSelectionRange();
	bool isSelectionActive();

	void goToAddress(bool selection);
	void searchRegEx();
	void findNext();

	void inputByte(uint8_t byte);
	void inputHexDigit(uint8_t digit);

	void adjustAddressAfterBackwardMovement();
	void adjustAddressAfterForwardMovement();

	void left(size_t count, bool selecting);
	void right(size_t count, bool selecting);
	void up(bool selecting);
	void down(bool selecting);
	void pageUp(bool selecting);
	void pageDown(bool selecting);
	void moveToStartOfLine(bool selecting);
	void moveToEndOfLine(bool selecting);
	void moveToStartOfView(bool selecting);
	void moveToEndOfView(bool selecting);
	void toggleHexOrAscii();
	void toggleInsertMode();
	void deleteBack();
	void deleteForward();

	BinaryViewRef m_data;
	ViewFrame* m_view;

	std::vector<HexEditorLine> m_lines;
	size_t m_topLine;
	uint64_t m_topAddr, m_bottomAddr;

	std::vector<BNAddressRange> m_ranges;
	uint64_t m_allocatedLength;
	uint64_t m_scrollBarMultiplier;
	int m_wheelDelta;
	bool m_updatingScrollBar;
	bool m_updatesRequired;

	uint64_t m_minAddr;
	uint64_t m_cursorAddr, m_prevCursorAddr;
	int m_cursorOffset;
	uint64_t m_selectionStartAddr;
	int m_cols, m_visibleRows;
	int m_lastMouseX, m_lastMouseY;
	bool m_selectionVisible;
	bool m_cursorAscii;
	bool m_caretVisible, m_caretBlink;
	bool m_insertMode;
	QString m_status;
	QTimer* m_cursorTimer;
	QTimer* m_updateTimer;
	Qt::KeyboardModifiers m_ctrl, m_command;

	RenderContext m_render;
	HexEditorHighlightState m_highlightState;

	ContextMenuManager m_contextMenuManager;

protected:
	virtual void resizeEvent(QResizeEvent* event) override;
	virtual void paintEvent(QPaintEvent* event) override;
	virtual void focusInEvent(QFocusEvent* event) override;
	virtual void focusOutEvent(QFocusEvent* event) override;
	virtual void keyPressEvent(QKeyEvent* event) override;
	virtual void keyReleaseEvent(QKeyEvent* event) override;
	virtual void mousePressEvent(QMouseEvent* event) override;
	virtual void mouseMoveEvent(QMouseEvent* event) override;
	virtual bool event(QEvent* event) override;
	virtual void wheelEvent(QWheelEvent* event) override;

Q_SIGNALS:

public Q_SLOTS:
	void disassembly();
	void createFunc();
	void createFuncWithPlatform(PlatformRef platform);

private Q_SLOTS:
	void scrollBarMoved(int value);
	void scrollBarAction(int action);
	void cursorTimerEvent();
	void updateTimerEvent();
};

class HexEditorViewType: public ViewType
{
	static HexEditorViewType* m_instance;

public:
	HexEditorViewType();
	virtual int getPriority(BinaryViewRef data, const QString& filename) override;
	virtual QWidget* create(BinaryViewRef data, ViewFrame* viewFrame) override;
	virtual QString getDisplayName(BinaryViewTypeRef type) override;
	virtual QString getDisplayLongName(BinaryViewTypeRef type) override;
	static void init();
};
