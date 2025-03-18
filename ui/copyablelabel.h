#include <QLabel>
#include "uitypes.h"

class BINARYNINJAUIAPI CopyableLabel: public QLabel
{
	QColor m_desiredColor {};
	QString m_hiddenText;

public:
	CopyableLabel(const QString& text, const QColor& color);
	void setHiddenText(const QString& text);
	void enterEvent(QEnterEvent* event) override;
	void leaveEvent(QEvent* event) override;
	void mousePressEvent(QMouseEvent* event) override;
};
