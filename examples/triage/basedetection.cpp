#include "basedetection.h"

using namespace BinaryNinja;
using namespace std;

BaseDetection::BaseDetection(BinaryViewRef bv, std::string arch, std::string analysis, uint32_t minStr, uint32_t pageSize)
{
	this->m_view = bv->GetParentView() ? bv->GetParentView() : bv;
	m_logger = LogRegistry::CreateLogger("TriageView.BaseDetection");
	m_logger->LogDebug(
		"Base Address Detection:\n"
		"\tArchitecture:       %s\n"
		"\tAnalysis Level:     %s\n"
		"\tMin. String Length: %d\n"
		"\tPage Size:          %08x",
		arch.c_str(),
		analysis.c_str(),
		minStr,
		pageSize
	);
}

void BaseDetectionWidget::detectBaseAddress()
{
	m_detectBaseAddressButton->setEnabled(false);

	// TODO: sanitize the inputs and support hex integers prefixed by 0x
	BaseDetection(
		this->m_view,
		m_inputs->ArchitectureBox->currentText().toStdString(),
		m_inputs->AnalysisBox->currentText().toStdString(),
		m_inputs->StrlenLineEdit->text().toInt(),
		m_inputs->PageSizeLineEdit->text().toInt()
	);
}

BaseDetectionWidget::BaseDetectionWidget(QWidget* parent, BinaryViewRef bv)
{
	m_view = bv->GetParentView() ? bv->GetParentView() : bv;
	this->m_layout = new QGridLayout();
	auto& [row, column] = this->m_fieldPosition;

	m_inputs = new BaseDetectionWidgetInputs();
	this->m_layout->addWidget(new QLabel("Architecture:"), row, column);
	m_inputs->ArchitectureBox = new QComboBox(this);
	auto archItemList = QStringList();
	archItemList << "auto detect";
	auto architectures = Architecture::GetList();
	for (const auto& arch : architectures)
		archItemList << QString::fromStdString(arch->GetName());
	m_inputs->ArchitectureBox->addItems(archItemList);
	this->m_layout->addWidget(m_inputs->ArchitectureBox, row++, column + 1);

	this->m_layout->addWidget(new QLabel("Analysis Level:"), row, column);
	m_inputs->AnalysisBox = new QComboBox(this);
	auto analysisItemList = QStringList() << "basic" << "controlFlow" << "full";
	m_inputs->AnalysisBox->addItems(analysisItemList);
	this->m_layout->addWidget(m_inputs->AnalysisBox, row++, column + 1);

	this->m_layout->addWidget(new QLabel("Min. String Length:"), row, column);
	m_inputs->StrlenLineEdit = new QLineEdit("10");
	this->m_layout->addWidget(m_inputs->StrlenLineEdit, row++, column + 1);

	this->m_layout->addWidget(new QLabel("Page Size:"), row, column);
	m_inputs->PageSizeLineEdit = new QLineEdit("1000");
	this->m_layout->addWidget(m_inputs->PageSizeLineEdit, row++, column + 1);

	m_detectBaseAddressButton = new QPushButton("Start Detection");
	connect(m_detectBaseAddressButton, &QPushButton::clicked, this, &BaseDetectionWidget::detectBaseAddress);
	this->m_layout->addWidget(m_detectBaseAddressButton, row, column);

	const auto scaledWidth = UIContext::getScaledWindowSize(20, 20).width();
	this->m_layout->setColumnMinimumWidth(BaseDetectionWidget::m_maxColumns * 3 - 1, scaledWidth);
	this->m_layout->setColumnStretch(BaseDetectionWidget::m_maxColumns * 3 - 1, 1);
	setLayout(this->m_layout);
}