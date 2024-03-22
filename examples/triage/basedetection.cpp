#include "basedetection.h"

using namespace BinaryNinja;
using namespace std;

BaseDetection::BaseDetection(BinaryViewRef bv, BaseDetectionSettings& settings)
{
	m_view = bv->GetFile()->GetViewOfType("Raw");
	m_logger = LogRegistry::CreateLogger("TriageView.BaseDetection");
	m_settings = settings;
	m_logger->LogDebug(
		"BaseDetection:\n"
		"\tArchitecture:       %s\n"
		"\tAnalysis Level:     %s\n"
		"\tMin. String Length: %d\n"
		"\tPage Size:          %08x",
		m_settings.Architecture.c_str(),
		m_settings.Analysis.c_str(),
		m_settings.MinStrlen,
		m_settings.PageSize
	);
}

void BaseDetection::runAnalysis()
{
	auto loadSettings = Settings::Instance();
	map<string, Ref<Metadata>> metadataMap =
	{
		{"loader.imageBase", new Metadata((uint64_t) 0)},
		{"analysis.mode", new Metadata(m_settings.Analysis)},
		{"analysis.limits.minStringLength", new Metadata((uint64_t) m_settings.MinStrlen)},
		{"analysis.linearSweep.permissive", new Metadata(true)}
	};
	if (m_settings.Architecture != "auto detect")
		metadataMap["loader.architecture"] = new Metadata(m_settings.Architecture);
	Ref<Metadata> options = new Metadata(metadataMap);
	m_view = Load(m_view, true, nullptr, options);
}

void BaseDetection::identifyPointsOfInterest()
{
	if (!m_view || !m_view->HasInitialAnalysis())
	{
		m_logger->LogError("BaseDetection: view is not initialized!?");
		return;
	}

	for (const auto& func : m_view->GetAnalysisFunctionList())
	{
		m_funcOffsets.insert(func->GetStart());
	}

	m_logger->LogDebug("BaseDetection: identified %d functions", m_funcOffsets.size());
}

void BaseDetection::DetectBaseAddress()
{
	this->runAnalysis();
	this->identifyPointsOfInterest();
}

void BaseDetectionThread::run()
{
	QString result; // TODO - final results will be more than a string

	// TODO: sanatize inputs (handle when users input strings for ints, etc..)
	BaseDetectionSettings settings = {
		m_inputs->ArchitectureBox->currentText().toStdString(),
		m_inputs->AnalysisBox->currentText().toStdString(),
		m_inputs->StrlenLineEdit->text().toInt(),
		m_inputs->PageSizeLineEdit->text().toInt()
	};

	auto baseDetection = BaseDetection(m_view, settings);
	baseDetection.DetectBaseAddress();
	emit resultReady(result);
}

void BaseDetectionWidget::handleResults(const QString& result)
{
	m_detectBaseAddressButton->setEnabled(true);
	// TODO: handle results and update the UI
}

void BaseDetectionWidget::detectBaseAddress()
{
	m_detectBaseAddressButton->setEnabled(false);
	auto workerThread = new BaseDetectionThread(&m_inputs, m_view);
	connect(workerThread, &BaseDetectionThread::resultReady, this, &BaseDetectionWidget::handleResults);
	connect(workerThread, &BaseDetectionThread::finished, workerThread, &QObject::deleteLater);
	workerThread->start();
}

BaseDetectionWidget::BaseDetectionWidget(QWidget* parent, BinaryViewRef bv)
{
	m_view = bv->GetParentView() ? bv->GetParentView() : bv;
	this->m_layout = new QGridLayout();
	auto& [row, column] = this->m_fieldPosition;

	this->m_layout->addWidget(new QLabel("Architecture:"), row, column);
	m_inputs.ArchitectureBox = new QComboBox(this);
	auto archItemList = QStringList();
	archItemList << "auto detect";
	auto architectures = Architecture::GetList();
	for (const auto& arch : architectures)
		archItemList << QString::fromStdString(arch->GetName());
	m_inputs.ArchitectureBox->addItems(archItemList);
	this->m_layout->addWidget(m_inputs.ArchitectureBox, row++, column + 1);

	this->m_layout->addWidget(new QLabel("Analysis Level:"), row, column);
	m_inputs.AnalysisBox = new QComboBox(this);
	auto analysisItemList = QStringList() << "basic" << "controlFlow" << "full";
	m_inputs.AnalysisBox->addItems(analysisItemList);
	this->m_layout->addWidget(m_inputs.AnalysisBox, row++, column + 1);

	this->m_layout->addWidget(new QLabel("Min. String Length:"), row, column);
	m_inputs.StrlenLineEdit = new QLineEdit("10");
	this->m_layout->addWidget(m_inputs.StrlenLineEdit, row++, column + 1);

	this->m_layout->addWidget(new QLabel("Page Size:"), row, column);
	m_inputs.PageSizeLineEdit = new QLineEdit("1000");
	this->m_layout->addWidget(m_inputs.PageSizeLineEdit, row++, column + 1);

	m_detectBaseAddressButton = new QPushButton("Start Detection");
	connect(m_detectBaseAddressButton, &QPushButton::clicked, this, &BaseDetectionWidget::detectBaseAddress);
	this->m_layout->addWidget(m_detectBaseAddressButton, row, column);

	const auto scaledWidth = UIContext::getScaledWindowSize(20, 20).width();
	this->m_layout->setColumnMinimumWidth(BaseDetectionWidget::m_maxColumns * 3 - 1, scaledWidth);
	this->m_layout->setColumnStretch(BaseDetectionWidget::m_maxColumns * 3 - 1, 1);
	setLayout(this->m_layout);
}