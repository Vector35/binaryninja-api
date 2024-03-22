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
		"\tPage Size:          %llx",
		m_settings.Architecture.c_str(),
		m_settings.Analysis.c_str(),
		m_settings.MinStrlen,
		m_settings.PageSize
	);
}

bool BaseDetection::Init()
{
	auto loadSettings = Settings::Instance();
	map<string, Ref<Metadata>> metadataMap = {
		{"loader.imageBase", new Metadata((uint64_t) 0)},
		{"analysis.mode", new Metadata(m_settings.Analysis)},
		{"analysis.limits.minStringLength", new Metadata((uint64_t) m_settings.MinStrlen)},
		{"analysis.linearSweep.permissive", new Metadata(true)}
	};
	if (m_settings.Architecture != "auto detect")
		metadataMap["loader.architecture"] = new Metadata(m_settings.Architecture);

	Ref<Metadata> options = new Metadata(metadataMap);
	m_view = Load(m_view, true, nullptr, options);
	if (!m_view)
	{
		m_logger->LogError("BaseDetection: failed to initialize view!?");
		return false;
	}

	auto platform = m_view->GetDefaultPlatform();
	if (!platform)
	{
		m_logger->LogError("BaseDetection: failed to initialize platform from view!?");
		return false;
	}

	m_arch = platform->GetArchitecture();
	if (!m_arch)
	{
		m_logger->LogError("BaseDetection: failed to initialize architecture from view!?");
		return false;
	}

	m_reader = new BinaryReader(m_view, m_arch->GetEndianness());
	if (!m_reader)
	{
		m_logger->LogError("BaseDetection: failed to initialize BinaryReader!?");
		return false;
	}

	return true;
}

bool BaseDetection::identifyPointsOfInterest()
{
	if (!m_view || !m_view->HasInitialAnalysis())
	{
		m_logger->LogError("BaseDetection: view is not initialized!?");
		return false;
	}

	for (const auto& func : m_view->GetAnalysisFunctionList())
	{
		m_funcOffsets.insert(func->GetStart());
	}

	// TODO: implement a better method for string detection. Linear sweep is running in permissive
	// mode without sections and we're only doing "basic" analysis
	for (const auto& str : m_view->GetStrings())
	{
		m_stringOffsets.insert(str.start);
	}

	if (m_funcOffsets.size() + m_stringOffsets.size() == 0)
	{
		m_logger->LogError("BaseDetection: no points of interest identified");
		return false;
	}

	m_logger->LogDebug(
		"BaseDetection: identified %d functions and %d strings",
		m_funcOffsets.size(),
		m_stringOffsets.size()
	);

	return true;
}

bool BaseDetection::tryReadPointerAt(uint64_t offset, uint64_t& value)
{
	m_reader->Seek(offset);
	return m_reader->TryReadPointer(value);
}

std::vector<std::set<uint64_t>> BaseDetection::groupClusteredPointers()
{
	std::vector<std::set<uint64_t>> clusters;
	std::set<uint64_t> cluster;
	uint64_t fileSize = m_view->GetLength();
	uint64_t prev = 0;
	for (auto& pointer : m_pointers)
	{
		if (prev && pointer - prev > fileSize)
		{
			if (cluster.size() >= MIN_POINTER_THRESHOLD)
				clusters.push_back(cluster);
			cluster.clear();
		}

		cluster.insert(pointer);
		prev = pointer;
	}

	clusters.push_back(cluster);
	return clusters;
}

std::vector<std::set<uint64_t>> BaseDetection::identifyRangesFromClusteredPointers(std::vector<std::set<uint64_t>>& clusters)
{
	uint64_t pageAlignMask = ~(m_settings.PageSize - 1);
	uint64_t halfFileSize = m_view->GetLength() / 2;
	std::vector<std::set<uint64_t>> ranges;
	std::set<uint64_t> range;
	for (auto& cluster : clusters)
	{
		// Start is the first pointer minus half the size of the file (aligned to page boundary)
		uint64_t start = *cluster.begin();
		start = start < halfFileSize ? 0 : start - halfFileSize;
		start &= pageAlignMask;

		// End is last pointer + half the size of the file (aligned to a page boundary)
		uint64_t end = *cluster.rbegin();
		uint64_t tmp = end + halfFileSize;
		end = end > tmp ? std::numeric_limits<uint64_t>::max() : tmp;
		end &= pageAlignMask;;

		range.insert(start);
		range.insert(end);
		ranges.push_back(range);
		range.clear();
	}

	return ranges;
}

bool BaseDetection::identifyPointers()
{
	// TODO: find pointers via LLIL analysis
	uint64_t pointer;
	uint64_t pointerSize = m_arch->GetAddressSize();
	for (auto& [offset, variable] : m_view->GetDataVariables())
	{
		m_dataVariableOffsets.insert(offset);
		if (variable.type->IsPointer() || (variable.type->IsInteger() && variable.type->GetWidth() == pointerSize))
		{
			// Global variable is a pointer or it's pointer width
			if (!tryReadPointerAt(offset, pointer))
				continue;

			m_pointers.insert(pointer);
		}
	}

	if (m_pointers.size() == 0)
	{
		m_logger->LogError("BaseDetection: no pointers identified");
		return false;
	}

	m_logger->LogDebug("BaseDetection: identified %d pointers", m_pointers.size());
	/*
	for (auto& pointer : m_pointers)
		m_logger->LogDebug("BaseDetection: pointer: %llx", pointer);
	*/

	return true;
}

void BaseDetection::DetectBaseAddress()
{
	if (!this->identifyPointsOfInterest())
		return;

	if (!this->identifyPointers())
		return;

	auto clusteredPointers = this->groupClusteredPointers();
	if (clusteredPointers.empty())
	{
		m_logger->LogError("BaseDetection: no pointer clusters found");
		return;
	}

	auto searchRanges = identifyRangesFromClusteredPointers(clusteredPointers);
	for (size_t i = 0; i < searchRanges.size(); i++)
	{
		m_logger->LogDebug("BaseDetection: range #%d", i);
		for (auto& range : searchRanges[i])
		{
			m_logger->LogDebug("BaseDetection:  -- range: %llx", range);
		}
	}

	// TODO: brute force
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
	if (!baseDetection.Init()) {
		emit resultReady(result);
		return;
	}

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
	m_inputs.PageSizeLineEdit = new QLineEdit("1024");
	this->m_layout->addWidget(m_inputs.PageSizeLineEdit, row++, column + 1);

	m_detectBaseAddressButton = new QPushButton("Start Detection");
	connect(m_detectBaseAddressButton, &QPushButton::clicked, this, &BaseDetectionWidget::detectBaseAddress);
	this->m_layout->addWidget(m_detectBaseAddressButton, row, column);

	const auto scaledWidth = UIContext::getScaledWindowSize(20, 20).width();
	this->m_layout->setColumnMinimumWidth(BaseDetectionWidget::m_maxColumns * 3 - 1, scaledWidth);
	this->m_layout->setColumnStretch(BaseDetectionWidget::m_maxColumns * 3 - 1, 1);
	setLayout(this->m_layout);
}