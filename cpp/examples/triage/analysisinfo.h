#pragma once

#include <QtWidgets/QWidget>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QLabel>
#include "uitypes.h"
#include "headers.h"

class TriageView;

class AnalysisInfoWidget : public QWidget
{
	static constexpr std::int32_t m_maxColumns {2};
	BinaryViewRef m_data;
	QGridLayout* m_layout {};
	NavigationAddressLabel* m_gpLabel;
	QLabel* m_gpExtraLabel;

	BinaryNinja::Confidence<BinaryNinja::RegisterValue> m_lastGPValue;

	void updateDisplay();

public:
	AnalysisInfoWidget(QWidget* parent, BinaryViewRef data);
	virtual ~AnalysisInfoWidget();

private Q_SLOTS:
	void timerExpired();
};
