#pragma once

#include <QtWidgets/QAbstractScrollArea>
#include "viewframe.h"
#include "render.h"


struct ByteViewLine
{
	uint64_t address;
	size_t length;
	QString text;
	bool separator;
};


class ByteView: public QAbstractScrollArea, public View
{
	BinaryViewRef m_data;
	RenderContext m_render;

	uint64_t m_cursorAddr, m_prevCursorAddr, m_selectionStartAddr, m_topAddr, m_bottomAddr;
	bool m_selectionVisible;
	size_t m_cols, m_visibleRows, m_addrWidth;

	bool m_updatesRequired;
	QTimer* m_updateTimer;

	std::vector<ByteViewLine> m_lines;
	size_t m_topLine;

	std::vector<BNAddressRange> m_ranges;
	uint64_t m_allocatedLength, m_scrollBarMultiplier;

	int m_lastMouseX, m_lastMouseY;
	int m_wheelDelta;
	bool m_updatingScrollBar;

	bool m_caretVisible, m_caretBlink;
	QTimer* m_cursorTimer;

	void updateRanges();
	void removeRange(uint64_t begin, uint64_t end);

	void setTopToAddress(uint64_t addr);

	void adjustSize(int width, int height);

	uint64_t getContiguousOffsetForAddress(uint64_t addr);
	uint64_t getAddressForContiguousOffset(uint64_t offset);

	void refreshLines();
	void refreshAtCurrentLocation();

	ByteViewLine createLine(uint64_t addr, size_t length, bool separator);
	bool cachePreviousLines();
	bool cacheNextLines();
	void updateCache();
	void scrollLines(int count);
	void showContextAroundTop();
	void repositionCaret();
	void updateCaret();

	void adjustAddressAfterBackwardMovement();
	void adjustAddressAfterForwardMovement();
	void left(int count, bool selecting);
	void right(int count, bool selecting);
	void up(bool selecting);
	void down(bool selecting);
	void pageUp(bool selecting);
	void pageDown(bool selecting);
	void moveToStartOfLine(bool selecting);
	void moveToEndOfLine(bool selecting);
	void moveToStartOfView(bool selecting);
	void moveToEndOfView(bool selecting);

	uint64_t addressFromLocation(int x, int y);

public:
	ByteView(QWidget* parent, BinaryViewRef data);

	virtual BinaryViewRef getData() override;
	virtual QFont getFont() override;
	virtual uint64_t getCurrentOffset() override;
	virtual BNAddressRange getSelectionOffsets() override;
	virtual bool navigate(uint64_t addr) override;
	virtual void updateFonts() override;
	virtual void selectAll();
	virtual void selectNone();

	uint64_t getStart();
	uint64_t getEnd();
	uint64_t getLength();

protected:
	virtual void resizeEvent(QResizeEvent* event) override;
	virtual void paintEvent(QPaintEvent* event) override;
	virtual void wheelEvent(QWheelEvent* event) override;
	virtual void focusInEvent(QFocusEvent* event) override;
	virtual void focusOutEvent(QFocusEvent* event) override;
	virtual void mousePressEvent(QMouseEvent* event) override;
	virtual void mouseMoveEvent(QMouseEvent* event) override;

private Q_SLOTS:
	void scrollBarMoved(int value);
	void scrollBarAction(int action);
	void cursorTimerEvent();
};


class ByteViewType: public ViewType
{
public:
	ByteViewType();
	virtual int getPriority(BinaryViewRef data, const QString& filename) override;
	virtual QWidget* create(BinaryViewRef data, ViewFrame* frame) override;
};
