#pragma once

#include <QtGui/QColor>
#include <QtGui/QPainter>
#include <QtWidgets/QLabel>


class BINARYNINJAUIAPI ClickableLabel: public QLabel
{
	Q_OBJECT

public:
	ClickableLabel(QWidget* parent = nullptr, const QString& name = ""): QLabel(parent) { setText(name); }

Q_SIGNALS:
	void clicked();

protected:
	void mouseReleaseEvent(QMouseEvent* event) override { if (event->button() == Qt::LeftButton) Q_EMIT clicked(); }
};


class BINARYNINJAUIAPI ClickableStateLabel: public ClickableLabel
{
	Q_OBJECT

	QString m_name;
	QString m_altName;
	bool m_state = true;
	bool m_stateEffectEnabled = false;
	bool m_altStateEffect = false;
	QPalette::ColorRole m_altOverlayColorRole;
	int m_alpha;

public:
	ClickableStateLabel(QWidget* parent, const QString& name, const QString& altName): ClickableLabel(parent, name), m_name(name), m_altName(altName) { }

	void setDisplayState(bool state) {
		m_state = state;
		setText(m_state ? m_name : m_altName);
	}

	void setAlternateTransparency(QPalette::ColorRole colorRole, int alpha, bool state) {
		m_altOverlayColorRole = colorRole;
		m_alpha = alpha;
		m_altStateEffect = state;
		m_stateEffectEnabled = true;
	}

protected:
	void paintEvent(QPaintEvent* event) override {
		ClickableLabel::paintEvent(event);
		if (m_stateEffectEnabled && (m_state == m_altStateEffect))
		{
			QPainter p(this);
			QColor overlayColor = palette().color(m_altOverlayColorRole);
			overlayColor.setAlpha(m_alpha);
			p.fillRect(event->rect(), overlayColor);
		}
	}
};
