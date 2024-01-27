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
#include "dockhandler.h"
#include "uitypes.h"

class ContextMenuManager;
class Menu;
class View;
class SplitPaneWidget;

/*!

	\defgroup featuremap FeatureMap
 	\ingroup uiapi
*/

/*!

    \ingroup featuremap
*/
class BINARYNINJAUIAPI FeatureMap : public QWidget, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

	QImage* m_image = nullptr;
	QImage* m_staticImage = nullptr;
	std::vector<std::pair<uint64_t, uint64_t>> m_regions;

	SplitPaneWidget* m_owner = nullptr;
	BinaryViewRef m_data;

	bool m_updatesPending = false;
	QTimer* m_updateTimer = nullptr;
	size_t m_bvWidth = 0;
	size_t m_bvHeight = 0;
	uint64_t m_bvLength = 0;

	bool m_naturalOrientation;

	int m_curLocX = 0;
	int m_curLocY = 0;
	uint64_t m_curAddr = 0;
	bool m_navigationInProgress = false;

	QVector<QColor> m_colors;
	QVector<QRgb> m_colorTable;

	Menu m_menu;
	ContextMenuManager* m_contextMenuManager;

	class BackgroundRefresh : public BinaryNinja::RefCountObject
	{
		std::mutex m_mutex;
		bool m_valid;
		QPointer<FeatureMap> m_featureMap;

	  public:
		BackgroundRefresh(FeatureMap* featureMap);
		void start();
		void abort();
	};

	BinaryNinja::Ref<BackgroundRefresh> m_backgroundRefresh = nullptr;

	void updateCoordinates();

  public:
	FeatureMap(SplitPaneWidget* owner, BinaryViewRef data, bool vertical = true);
	virtual ~FeatureMap();

	void backgroundRefresh();
	std::pair<uint64_t, bool> getLinearOffsetForAddress(uint64_t addr);

	void notifyOffsetChanged(uint64_t offset);
	void notifyThemeChanged();

	void renderDataVariable(const BinaryNinja::DataVariable& var, bool ignoreString = false);

	virtual void OnAnalysisFunctionAdded(BinaryNinja::BinaryView* data, BinaryNinja::Function* func) override;
	virtual void OnAnalysisFunctionRemoved(BinaryNinja::BinaryView* data, BinaryNinja::Function* func) override;
	virtual void OnAnalysisFunctionUpdated(BinaryNinja::BinaryView* data, BinaryNinja::Function* func) override;
	virtual void OnDataVariableAdded(BinaryNinja::BinaryView* data, const BinaryNinja::DataVariable& var) override;
	virtual void OnDataVariableRemoved(BinaryNinja::BinaryView* data, const BinaryNinja::DataVariable& var) override;
	virtual void OnDataVariableUpdated(BinaryNinja::BinaryView* data, const BinaryNinja::DataVariable& var) override;
	virtual void OnStringFound(BinaryNinja::BinaryView* data, BNStringType type, uint64_t offset, size_t len) override;
	virtual void OnStringRemoved(BinaryNinja::BinaryView* data, BNStringType type, uint64_t offset, size_t len) override;

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
	void refresh();
	void updateThemeInternal();
	void updateTimerEvent();
};
