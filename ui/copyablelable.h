#include <QLabel>
#include "uitypes.h"

class BINARYNINJAUIAPI CopyableLabel: public QLabel
{
	QColor m_desiredColor {};
	QString altText = "";

public:
	CopyableLabel(const QString& text, const QColor& color, bool show = true);
	void enterEvent(QEnterEvent* event) override;
	void leaveEvent(QEvent* event) override;
	void mousePressEvent(QMouseEvent* event) override;
};
