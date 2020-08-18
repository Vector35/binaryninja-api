#pragma once

#include <QtWidgets/QLabel>

class BINARYNINJAUIAPI ClickableLabel: public QLabel
{
	Q_OBJECT

public:
	ClickableLabel(QWidget* parent = nullptr, const QString& name = ""): QLabel(parent) { setText(name); }

signals:
	void clicked();

protected:
	void mouseReleaseEvent(QMouseEvent* event) override { if (event->button() == Qt::LeftButton) emit clicked(); }
};
