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
		"\tPage Size:          0x%llx",
		m_settings.Architecture.c_str(),
		m_settings.Analysis.c_str(),
		m_settings.MinStrlen,
		m_settings.PageSize
	);
}


bool BaseDetection::Init()
{
	m_abort = false;
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
		m_logger->LogError("Failed to initialize view!?");
		return false;
	}

	auto platform = m_view->GetDefaultPlatform();
	if (!platform)
	{
		m_logger->LogError("Failed to initialize platform from view!?");
		return false;
	}

	m_arch = platform->GetArchitecture();
	if (!m_arch)
	{
		m_logger->LogError("Failed to initialize architecture from view!?");
		return false;
	}

	m_reader = new BinaryReader(m_view, m_arch->GetEndianness());
	if (!m_reader)
	{
		m_logger->LogError("Failed to initialize BinaryReader!?");
		return false;
	}

	return true;
}


std::string BaseDetection::ConfidenceLevelToString(ConfidenceLevel level)
{
	switch (level)
	{
	case CONFIDENCE_UNASSIGNED:
		return "Unassigned";
	case CONFIDENCE_HIGH:
		return "High";
	case CONFIDENCE_LOW:
		return "Low";
	default:
		return "Unknown";
	}
}


std::string BaseDetection::POITypeToString(BaseDetectionPOIType type)
{
	switch (type)
	{
	case POI_STRING:
		return "string";
	case POI_FUNCTION:
		return "function";
	case POI_DATA_VARIABLE:
		return "data variable";
	case POI_FILE_END:
		return "file end";
	case POI_FILE_START:
		return "file start";
	default:
		return "unknown";
	}
}

bool BaseDetection::identifyPointsOfInterest()
{
	if (!m_view || !m_view->HasInitialAnalysis())
	{
		m_logger->LogError("View is not initialized!?");
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
		m_logger->LogError("No points of interest identified");
		return false;
	}

	m_logger->LogDebug(
		"Identified %d functions and %d strings",
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
		m_logger->LogError("No pointers identified");
		return false;
	}

	m_logger->LogDebug("Identified %d pointers", m_pointers.size());
	return true;
}


void BaseDetection::scrubLosingCandidates()
{
	while (m_candidateBaseAddresses.size() > MAX_CANDIDATE_BASE_ADDRESSES)
	{
		uint64_t baseaddr = m_candidateBaseAddresses.begin()->second;
		m_candidateBaseAddresses.erase(m_candidateBaseAddresses.begin());
		m_candidateBaseAddressReasons.erase(baseaddr);
	}
}


void BaseDetection::bruteForceSearch(std::vector<std::set<uint64_t>>& clusteredPointers, std::vector<std::set<uint64_t>>& ranges)
{
	size_t i = 0;
	uint64_t fileSize = m_view->GetLength();
	for (auto& range : ranges)
	{
		uint64_t start = *range.begin();
		uint64_t end = *range.rbegin();
		uint64_t baseaddr = start;
		size_t numAddresses = (end - start) / m_settings.PageSize;
		m_logger->LogDebug(
			"Checking %zu base addresses from 0x%llx-0x%llx against %d pointers",
			numAddresses, start, end, clusteredPointers[i].size());
		while (baseaddr <= end)
		{
			if (m_abort)
			{
				m_logger->LogInfo("Analysis aborted by user");
				return;
			}

			size_t hits = 0;
			auto pointers = clusteredPointers[i];
			std::vector<BaseDetectionReason> reasons;
			for (auto& pointer : pointers)
			{
				for (auto& offset : m_stringOffsets)
				{
					if (baseaddr + offset == pointer)
					{
						reasons.push_back({pointer, offset, POI_STRING});
						hits++;
						break;
					}
				}

				for (auto& offset : m_funcOffsets)
				{
					if (baseaddr + offset == pointer)
					{
						reasons.push_back({pointer, offset, POI_FUNCTION});
						hits++;
						break;
					}
				}

				if (baseaddr + fileSize == pointer)
				{
					reasons.push_back({pointer, fileSize, POI_FILE_END});
					hits++;
					continue;
				}

				if (baseaddr == pointer)
				{
					reasons.push_back({pointer, 0, POI_FILE_START});
					hits++;
				}
			}

			if (hits > 0)
			{
				m_candidateBaseAddresses.insert({hits, baseaddr});
				m_candidateBaseAddressReasons[baseaddr] = reasons;
				reasons.clear();
				if (m_candidateBaseAddresses.size() >= SCRUB_LOSING_CANDIDATES_THRESHOLD)
					scrubLosingCandidates();
			}

			baseaddr += m_settings.PageSize;
		}

		i++;
	}	
}


void BaseDetection::DetectBaseAddress()
{
	if (!identifyPointsOfInterest())
		return;

	if (!identifyPointers())
		return;

	auto clusteredPointers = groupClusteredPointers();
	if (clusteredPointers.empty())
	{
		m_logger->LogError("No pointer clusters found");
		return;
	}

	auto searchRanges = identifyRangesFromClusteredPointers(clusteredPointers);
	bruteForceSearch(clusteredPointers, searchRanges);
}

#define MIN_HITS_FOR_HIGH_CONFIDENCE 10
#define MIN_HIT_DIFFERENCE_FOR_HIGH_CONFIDENCE 10
ConfidenceLevel BaseDetection::getConfidenceLevel()
{
	if (m_candidateBaseAddresses.empty())
		return CONFIDENCE_UNASSIGNED;

	size_t firstHits = m_candidateBaseAddresses.rbegin()->first;
	if (m_candidateBaseAddresses.size() == 1)
	{
		if (firstHits >= MIN_HITS_FOR_HIGH_CONFIDENCE)
			return CONFIDENCE_HIGH;
		else
			return CONFIDENCE_LOW;
	}

	size_t secondHits = std::prev(m_candidateBaseAddresses.end(), 2)->first;
	if (firstHits - secondHits >= MIN_HIT_DIFFERENCE_FOR_HIGH_CONFIDENCE)
		return CONFIDENCE_HIGH;

	return CONFIDENCE_LOW;
}


void BaseDetection::GetResults(BaseDetectionResults& results)
{
	if (m_candidateBaseAddresses.empty())
	{
		m_logger->LogError("No candidate base addresses found");
		return;
	}

	size_t i = 0;
	for (auto rit = m_candidateBaseAddresses.rbegin(); rit != m_candidateBaseAddresses.rend(); rit++)
	{
		if (i == MAX_CANDIDATE_BASE_ADDRESSES)
			break;

		auto [hits, baseaddr] = *rit;
		results.Scores.insert({hits, baseaddr});
		results.Reasons[baseaddr] = m_candidateBaseAddressReasons[baseaddr];
		m_logger->LogDebug("candidate base address: 0x%llx hits: %zu", baseaddr, hits);
		for (auto& reason : m_candidateBaseAddressReasons[baseaddr])
		{
			m_logger->LogDebug(
				"\t0x%llx points to POI type \"%s\" at offset 0x%llx",
				reason.Pointer, POITypeToString(reason.POIType).c_str(), reason.POIOffset);
		}
		i++;
	}

	results.Confidence = getConfidenceLevel();
}


void BaseDetectionThread::run()
{
	BaseDetectionResults results;

	// TODO: sanitize inputs (handle when users input strings for ints, etc..)
	BaseDetectionSettings settings = {
		m_inputs->ArchitectureBox->currentText().toStdString(),
		m_inputs->AnalysisBox->currentText().toStdString(),
		m_inputs->StrlenLineEdit->text().toInt(),
		m_inputs->PageSizeLineEdit->text().toInt()
	};

	auto baseDetection = BaseDetection(m_view, settings);
	if (!baseDetection.Init()) {
		emit resultReady(results);
		return;
	}

	baseDetection.DetectBaseAddress();
	baseDetection.GetResults(results);
	emit resultReady(results);
}


void BaseDetectionWidget::handleResults(const BaseDetectionResults& results)
{
	if (results.Scores.empty())
	{
		m_preferred_base->setText("No results");
		m_confidence->setText("Not available");
	}
	else
	{
		m_preferred_base->setText("0x" + QString::number(results.Scores.rbegin()->second, 16));
		m_confidence->setText(QString::fromStdString(BaseDetection::ConfidenceLevelToString(results.Confidence)) + " (Score: " + QString::number(results.Scores.rbegin()->first) + ")");
	}

	m_resultsTableWidget->clearContents();
	size_t numRows = 0;
	for (auto rit = results.Scores.rbegin(); rit != results.Scores.rend(); rit++)
	{
		numRows += results.Reasons.at(rit->second).size();
	}

	m_resultsTableWidget->setRowCount(numRows);
	size_t row = 0;
	for (auto rit = results.Scores.rbegin(); rit != results.Scores.rend(); rit++)
	{
		auto [score, baseaddr] = *rit;
		for (const auto& reason : results.Reasons.at(baseaddr))
		{
			m_resultsTableWidget->setItem(row, 0, new QTableWidgetItem("0x" + QString::number(baseaddr, 16)));
			m_resultsTableWidget->setItem(row, 1, new QTableWidgetItem("0x" + QString::number(reason.Pointer, 16)));
			m_resultsTableWidget->setItem(row, 2, new QTableWidgetItem("0x" + QString::number(reason.POIOffset, 16)));
			m_resultsTableWidget->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(BaseDetection::POITypeToString(reason.POIType))));
			row++;
		}
	}

	m_detectBaseAddressButton->setEnabled(true);
	m_abortButton->setHidden(true);
}


void BaseDetectionWidget::detectBaseAddress()
{
	m_preferred_base->setText("Detecting...");
	m_detectBaseAddressButton->setEnabled(false);
	auto workerThread = new BaseDetectionThread(&m_inputs, m_view);
	connect(workerThread, &BaseDetectionThread::resultReady, this, &BaseDetectionWidget::handleResults);
	connect(workerThread, &BaseDetectionThread::finished, workerThread, &QObject::deleteLater);
	workerThread->start();
	m_abortButton->setHidden(false);
}


void BaseDetectionWidget::abortAnalysis()
{
	BaseDetection::AbortAnalysis();
	m_abortButton->setHidden(true);
}


BaseDetectionWidget::BaseDetectionWidget(QWidget* parent, BinaryViewRef bv)
{
	m_view = bv->GetParentView() ? bv->GetParentView() : bv;
	m_layout = new QGridLayout();
	auto& [row, column] = m_fieldPosition;

	m_layout->addWidget(new QLabel("Architecture:"), row, column);
	m_inputs.ArchitectureBox = new QComboBox(this);
	auto archItemList = QStringList();
	archItemList << "auto detect";
	auto architectures = Architecture::GetList();
	for (const auto& arch : architectures)
		archItemList << QString::fromStdString(arch->GetName());
	m_inputs.ArchitectureBox->addItems(archItemList);
	m_layout->addWidget(m_inputs.ArchitectureBox, row++, column + 1, Qt::AlignLeft);

	m_layout->addWidget(new QLabel("Analysis Level:"), row, column);
	m_inputs.AnalysisBox = new QComboBox(this);
	auto analysisItemList = QStringList() << "basic" << "controlFlow" << "full";
	m_inputs.AnalysisBox->addItems(analysisItemList);
	m_layout->addWidget(m_inputs.AnalysisBox, row++, column + 1, Qt::AlignLeft);

	m_layout->addWidget(new QLabel("Min. String Length:"), row, column);
	m_inputs.StrlenLineEdit = new QLineEdit("10");
	m_layout->addWidget(m_inputs.StrlenLineEdit, row++, column + 1, Qt::AlignLeft);

	m_layout->addWidget(new QLabel("Page Size:"), row, column);
	m_inputs.PageSizeLineEdit = new QLineEdit("1024");
	m_layout->addWidget(m_inputs.PageSizeLineEdit, row++, column + 1, Qt::AlignLeft);

	m_detectBaseAddressButton = new QPushButton("Start Detection");
	connect(m_detectBaseAddressButton, &QPushButton::clicked, this, &BaseDetectionWidget::detectBaseAddress);
	m_layout->addWidget(m_detectBaseAddressButton, row, column, Qt::AlignLeft);

	m_abortButton = new QPushButton("Abort Analysis");
	connect(m_abortButton, &QPushButton::clicked, this, &BaseDetectionWidget::abortAnalysis);
	m_abortButton->setHidden(true);
	m_layout->addWidget(m_abortButton, row++, column + 1, Qt::AlignLeft);

	m_layout->addWidget(new QLabel("Preferred Base:"), row, column);
	m_preferred_base = new QLineEdit("Unknown");
	m_preferred_base->setReadOnly(true);
	m_layout->addWidget(m_preferred_base, row++, column + 1);

	m_layout->addWidget(new QLabel("Confidence:"), row, column);
	m_confidence = new QLineEdit("Not available");
	m_confidence->setReadOnly(true);
	m_layout->addWidget(m_confidence, row++, column + 1);

	m_resultsTableWidget = new QTableWidget(this);
	m_resultsTableWidget->setColumnCount(4);
	QStringList header;
	header << "Base Address" << "Pointer" << "POI Offset" << "POI Type";
	m_resultsTableWidget->setHorizontalHeaderLabels(header);
	m_resultsTableWidget->horizontalHeader()->setStretchLastSection(true);
	m_resultsTableWidget->verticalHeader()->setVisible(false);
	m_resultsTableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
	m_resultsTableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_resultsTableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
	m_resultsTableWidget->setMinimumHeight(150);
	m_layout->addWidget(m_resultsTableWidget, row++, column, 1, 2);
	setLayout(m_layout);
}