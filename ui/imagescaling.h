#pragma once

#include <QtGui/QImage>
#include <QtGui/QPixmap>
#include <QtWidgets/QLabel>
#include "uitypes.h"

// Resample at the physical size of the destination rather than downscaling in QPainter.
// The returned pixmap is cached by source, size, and device pixel ratio. GUI thread only.
QPixmap BINARYNINJAUIAPI pixmapForDisplay(const QPixmap& source, QSize logicalSize, qreal devicePixelRatio,
	Qt::AspectRatioMode aspectRatio = Qt::IgnoreAspectRatio);
QPixmap BINARYNINJAUIAPI pixmapForDisplay(const QImage& source, QSize logicalSize, qreal devicePixelRatio,
	Qt::AspectRatioMode aspectRatio = Qt::IgnoreAspectRatio);

// Keeps the full-resolution source and re-renders at the current screen's DPR on paint.
class BINARYNINJAUIAPI ScaledPixmapLabel : public QLabel
{
	QPixmap m_source;
	QSize m_preferredSize;
	Qt::AspectRatioMode m_aspectRatio;

public:
	ScaledPixmapLabel(const QPixmap& source, QSize preferredSize,
		Qt::AspectRatioMode aspectRatio = Qt::IgnoreAspectRatio, QWidget* parent = nullptr);
	void setSourcePixmap(const QPixmap& source);
	QSize sizeHint() const override { return m_preferredSize; }

protected:
	bool event(QEvent* event) override;
	void paintEvent(QPaintEvent* event) override;
};
