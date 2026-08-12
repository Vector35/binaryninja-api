#pragma once

#include <QtWidgets/QLineEdit>
#include "binaryninjaapi.h"
#include "uicontext.h"

/*!

	\defgroup filter Filter
 	\ingroup uiapi
*/

/*!

    \ingroup filter
*/
enum BINARYNINJAUIAPI FilterOption {
	NoFilterOption = 0,
	CaseSensitiveOption = 1,
	UseRegexOption = 2,
};

Q_DECLARE_FLAGS(FilterOptions, FilterOption)


/*!

    \ingroup filter
*/
class BINARYNINJAUIAPI FilterTarget
{
  public:
	virtual ~FilterTarget() {}

	virtual void setFilter(const std::string& filter, FilterOptions options) = 0;
	virtual void scrollToFirstItem() = 0;
	virtual void scrollToCurrentItem() = 0;

	// Select an item, typically the first, if none is already selected.
	virtual void ensureSelection() = 0;

	// Activate the selected item, typically in response to the user
	// pressing the return key.
	virtual void activateSelection() = 0;

	// Transfer focus away from the `FilterEdit`. By default, focus
	// is transferred to `this` if it is an instance of `QWidget`.
	virtual void closeFilter();
};

/*!

    \ingroup filter
*/
class BINARYNINJAUIAPI FilterEdit : public QLineEdit
{
	Q_OBJECT

	FilterTarget* m_target;
	FilterOptions m_filterOptions;

	QAction* m_clearAction;
	QAction* m_regexAction;
	QAction* m_regexWarningAction;
	QAction* m_caseSensitivityAction;

	QIcon getActionIcon(const QString& iconName, bool enabled) const;

  public:
	FilterEdit(FilterTarget* target);

	QAction* addFilterAction(const QString& iconName, const QString& toolTip, bool checkable = false);
	void setFilterActionActive(QAction* action, const QString& iconName, bool active);

	void showRegexToggle(bool enabled);

	void setRegexValidationError(const QString& error);

	FilterOptions getFilterOptions() const { return m_filterOptions; }

  Q_SIGNALS:
  	void optionsChanged(FilterOptions options);

  protected:
	virtual void paintEvent(QPaintEvent* event) override;
	virtual void keyPressEvent(QKeyEvent* event) override;
};

/*!

    \ingroup filter
*/
class BINARYNINJAUIAPI FilteredView : public QWidget
{
	Q_OBJECT

	FilterTarget* m_target;
	QWidget* m_widget;
	FilterEdit* m_filter;
	QTimer* m_timer;

  public:
	FilteredView(QWidget* parent, QWidget* filtered, FilterTarget* target, FilterEdit* edit = nullptr);
	void setFilterPlaceholderText(const QString& text);
	void setFilterToolTip(const QString& text);
	void updateFonts();
	void clearFilter();
	void showFilter(const QString& initialText);
	void focusAndSelectFilter();
	bool hasFilterText() const;

	static bool match(const std::string& name, const std::string& filter, bool caseSensitive = false);

  private Q_SLOTS:
	void timerStart();
	void filterChanged();
};
