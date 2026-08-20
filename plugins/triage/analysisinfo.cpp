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
	auto gpValues = m_data->GetGlobalPointerValues();
	if (gpValues == m_lastGPValues)
		return;

	m_lastGPValues = gpValues;
	updateDisplay();
}


void AnalysisInfoWidget::updateDisplay()
{
	auto defaultPlatform = m_data->GetDefaultPlatform();
	if (defaultPlatform)
	{
		auto callingConvention = defaultPlatform->GetDefaultCallingConvention();
		if (callingConvention)
		{
			auto gpValues = m_data->GetGlobalPointerValues();
			if (!gpValues.empty())
			{
				std::vector<std::string> gpStrings;
				auto arch = m_data->GetDefaultArchitecture();
				for (auto& [reg, value] : gpValues)
				{
					if (reg == BN_INVALID_REGISTER)
						continue;
					gpStrings.push_back(arch->GetRegisterName(reg) + "=" + getStringForRegisterValue(arch, value));
				}

				if (gpStrings.empty())
				{
					m_gpLabel->setText("N/A");
					m_gpExtraLabel->setText("");
					return;
				}

				std::string gpString;
				for (size_t i = 0; i < gpStrings.size(); i++)
				{
					if (i != 0)
						gpString += ", ";
					gpString += gpStrings[i];
				}

				std::string gpExtraString;
				if (m_data->UserGlobalPointerValueSet())
					gpExtraString = " (*)";

				m_gpLabel->setText(QString::fromStdString(gpString));
				m_gpExtraLabel->setText(QString::fromStdString(gpExtraString));
				return;
			}
		}
	}

	m_gpLabel->setText("N/A");
	m_gpExtraLabel->setText("");
}
