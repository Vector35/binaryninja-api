#pragma once

#include "uitypes.h"
#include <QtWidgets/QToolButton>
#include <QtCore/QParallelAnimationGroup>
#include <QtWidgets/QScrollArea>
#include <QtCore/QPropertyAnimation>

class BINARYNINJAUIAPI ExpandableGroup : public QWidget
{
	Q_OBJECT

private:
	QToolButton* m_button;
	QParallelAnimationGroup* m_animation;
	QScrollArea* m_content;
	int m_duration = 100;

public Q_SLOTS:
	void toggle(bool collapsed);

public:
	explicit ExpandableGroup(const QString& title = "", QWidget* parent = nullptr);
	void setContentLayout(QLayout* contentLayout);
	void setTitle(const QString& title) { m_button->setText(title); }
};
