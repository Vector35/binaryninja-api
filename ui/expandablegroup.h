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

  private Q_SLOTS:
	void toggled(bool expanded);

  public:
	explicit ExpandableGroup(
	    QLayout* contentLayout, const QString& title = "", QWidget* parent = nullptr, bool expanded = false);
	void setupAnimation(QLayout* contentLayout);
	void setTitle(const QString& title) { m_button->setText(title); }
	void toggle(bool expanded);
};
