#include <QtCore/QTimer>
#include "analysisinfo.h"
#include "fontsettings.h"
#include "util.h"

AnalysisInfoWidget::AnalysisInfoWidget(QWidget* parent, BinaryViewRef data): QWidget(parent), m_data(data)
{
	m_layout = new QGridLayout();
	m_layout->setContentsMargins(0, 0, 0, 0);
	m_layout->setVerticalSpacing(1);

	auto* gpValueLayout = new QHBoxLayout();
	gpValueLayout->setContentsMargins(0, 0, 0, 0);
	m_gpLabel = new NavigationAddressLabel("");
	m_gpLabel->setFont(getMonospaceFont(this));
	gpValueLayout->addWidget(m_gpLabel);

	m_gpExtraLabel = new QLabel;
	gpValueLayout->addWidget(m_gpExtraLabel);

	m_layout->addWidget(new QLabel("Global Pointer Value:"), 0, 0);
	m_layout->addLayout(gpValueLayout, 0, 1);

	const auto scaledWidth = UIContext::getScaledWindowSize(20, 20).width();
	this->m_layout->setColumnMinimumWidth(AnalysisInfoWidget::m_maxColumns * 3 - 1, scaledWidth);
	this->m_layout->setColumnStretch(AnalysisInfoWidget::m_maxColumns * 3 - 1, 1);
	setLayout(m_layout);

	updateDisplay();

	auto* timer = new QTimer(this);
	connect(timer, &QTimer::timeout, this, &AnalysisInfoWidget::timerExpired);
	timer->setInterval(100);
	timer->setSingleShot(false);
	timer->start();
}


AnalysisInfoWidget::~AnalysisInfoWidget()
{

}


void AnalysisInfoWidget::timerExpired()
{
	auto gpValue = m_data->GetGlobalPointerValue();
	if (gpValue == m_lastGPValue)
		return;

	m_lastGPValue = gpValue;
	updateDisplay();
}


void AnalysisInfoWidget::updateDisplay()
{
	auto callingConvention = m_data->GetDefaultPlatform()->GetDefaultCallingConvention();
	auto gpRegister = callingConvention->GetGlobalPointerRegister();
	std::string gpString, gpExtraString;
	if (gpRegister == BN_INVALID_REGISTER)
	{
		gpString = "N/A";
	}
	else
	{
		auto gpValue = m_data->GetGlobalPointerValue();
		gpString = getStringForRegisterValue(m_data->GetDefaultArchitecture(), gpValue);
		gpExtraString = std::string(" @ ") + m_data->GetDefaultArchitecture()->GetRegisterName(gpRegister);
		if (m_data->UserGlobalPointerValueSet())
			gpExtraString += " (*)";
	}

	m_gpLabel->setText(QString::fromStdString(gpString));
	m_gpExtraLabel->setText(QString::fromStdString(gpExtraString));
}
