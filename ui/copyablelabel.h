#include <QLabel>
#include "uitypes.h"

class BINARYNINJAUIAPI CopyableLabel: public QLabel
{
	Q_OBJECT

	QColor m_desiredColor {};
	QString m_hiddenText;
	QString m_copyText;

public:
	CopyableLabel(const QString& text, const QColor& color);
	void setHiddenText(const QString& text);
	void setCopyText(const QString& text);
	void enterEvent(QEnterEvent* event) override;
	void leaveEvent(QEvent* event) override;
	void mousePressEvent(QMouseEvent* event) override;
};
