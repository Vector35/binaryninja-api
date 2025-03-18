#pragma once

#include <QtGui/QColor>
#include <QtGui/QAction>
#include <QtGui/QImage>
#include <QtWidgets/QMenu>
#include <QtGui/QPainter>
#include <QtCore/QRect>
#include <QtCore/QPointer>
#include <QtCore/QTimer>
#include <QtCore/QVector>
#include <QtWidgets/QWidget>
#include <mutex>
#include <tuple>
#include <vector>

#include "binaryninjaapi.h"
#include "action.h"
#include "notificationsdispatcher.h"
#include "uitypes.h"

class ContextMenuManager;
class View;
class SplitPaneWidget;

/*!

	\defgroup featuremap FeatureMap
 	\ingroup uiapi
*/

/*!

    \ingroup featuremap
*/
class BINARYNINJAUIAPI FeatureMap : public QWidget
{
	Q_OBJECT

	std::vector<uint8_t> m_imageData;
	std::unique_ptr<QImage> m_image = nullptr;
	std::unique_ptr<QImage> m_staticImage = nullptr;
	std::vector<BNAddressRange> m_ranges;

	BinaryViewRef m_data;
	std::unique_ptr<NotificationsDispatcher> m_dispatcher = nullptr;

	std::atomic<bool> m_updatesPending = false;
	QTimer* m_updateTimer = nullptr;
	size_t m_imgWidth = 0;
	size_t m_imgHeight = 0;
	double m_verticalScaleFactor = 1.0;
	uint64_t m_bvLength = 0;

	bool m_verticalOrientation;

	int m_curLocX = 0;
	int m_curLocY = 0;
	uint64_t m_curAddr = 0;
	bool m_navigationInProgress = false;

	QVector<QColor> m_colors;
	QVector<QRgb> m_colorTable;

	Menu m_menu;
	ContextMenuManager* m_contextMenuManager;

	void updateCoordinates();
	void updateMappedRegions();

  public:
	FeatureMap(SplitPaneWidget* owner, BinaryViewRef data, bool vertical = true);
	virtual ~FeatureMap();

	void backgroundRefresh();
	std::pair<uint64_t, bool> getLinearOffsetForAddress(uint64_t addr);

	void notifyOffsetChanged(uint64_t offset);
	void notifyThemeChanged();

	void renderDataVariable(const BinaryNinja::DataVariable& var, bool ignoreString = false);

	uint8_t getSymbolColor(const SymbolRef& symbol);
	void drawImageRect(uint64_t addr, size_t len, uint8_t color);

	virtual QSize sizeHint() const override;

	static int defaultWidth() { return 64; }

protected:
	virtual void contextMenuEvent(QContextMenuEvent* event) override;
	virtual void mouseMoveEvent(QMouseEvent* event) override;
	virtual void mousePressEvent(QMouseEvent* event) override;
	virtual void resizeEvent(QResizeEvent* event) override;
	virtual void paintEvent(QPaintEvent* event) override;
	void scrollTo(int x, int y, bool addHistoryEntry = false);

  Q_SIGNALS:
	void notifyThemeUpdated();

  private Q_SLOTS:
	void renderAnalysisData();
	void updateThemeInternal();
};
