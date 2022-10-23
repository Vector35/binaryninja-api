#pragma once

#include <QtWidgets/QLabel>
#include "viewframe.h"
#include "menus.h"
#include "uicontext.h"

/*!

	\defgroup addressindicator AddressIndicator
 	\ingroup uiapi
*/

/*! Format for displaying offsets

    \ingroup addressindicator
*/
enum class OffsetFormat : char
{
	VirtualAddress,
	FileStart,
	SegmentStart,
	SectionStart,
	FunctionStart
};

/*! Format for displaying an address range

    \ingroup addressindicator
*/
enum class RangeFormat : char
{
	StartOnly,
	EndOnly,
	StartAndLength,
	StartAndEnd
};

/*! Options for displaying an address or address range

    \ingroup addressindicator
*/
struct DisplayOptions
{
	OffsetFormat format = OffsetFormat::VirtualAddress;
	RangeFormat rangeFormat = RangeFormat::StartAndEnd;
};

/*!

    \ingroup addressindicator
*/
class BINARYNINJAUIAPI AddressIndicator : public MenuHelper
{
	Q_OBJECT

	uint64_t m_begin, m_end;
	BinaryViewRef m_view;

	DisplayOptions m_options{};
	const DisplayOptions m_defaultOptions{};

	//! Format an offset as a string.
	//!
	//! \returns An empty string in case of failure.
	QString formatOffset(uint64_t, OffsetFormat) const;

	//! Format an address range as a string.
	//!
	//! \returns An empty string in case of failure.
	QString formatRange(uint64_t start, uint64_t end, RangeFormat, OffsetFormat) const;

	//! Create a QAction to copy a formatted offset/range.
	void addCopyAction(QMenu*, RangeFormat, OffsetFormat, QString help = "");

	//! Create a QAction to set the display format.
	void addDisplayAction(QMenu*, RangeFormat, OffsetFormat, QString help = "");

	//! Refresh the text displayed in the status bar.
	void updateDisplay();

public:
	AddressIndicator(QWidget* parent);

	void clear();
	void setOffsets(uint64_t begin, uint64_t end, BinaryViewRef view);

  protected:
	virtual void showMenu();
};
