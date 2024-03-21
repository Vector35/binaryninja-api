#include "baseaddress.h"

using namespace std;


BNBaseAddressDetectionPOISetting BaseAddressDetectionPOISettingFromString(const std::string& setting)
{
	if (setting == "Strings only")
		return POI_ANALYSIS_STRINGS_ONLY;
	if (setting == "Functions only")
		return POI_ANALYSIS_FUNCTIONS_ONLY;
	return POI_ANALYSIS_ALL; // Default to All
}


std::string BaseAddressDetectionPOITypeToString(BNBaseAddressDetectionPOIType type)
{
	switch (type)
	{
	case POI_STRING:
		return "String";
	case POI_FUNCTION:
		return "Function";
	case POI_DATA_VARIABLE:
		return "Data variable";
	case POI_FILE_END:
		return "File end";
	case POI_FILE_START:
		return "File start";
	default:
		return "Unknown";
	}
}


std::string BaseAddressDetectionConfidenceToString(BinaryNinja::BaseAddressDetectionConfidence level)
{
	switch (level)
	{
	case BinaryNinja::NoConfidence:
		return "Unassigned";
	case BinaryNinja::HighConfidence:
		return "High";
	case BinaryNinja::LowConfidence:
		return "Low";
	default:
		return "Unknown";
	}
}


uint32_t HexOrDecimalQStringToUint32(const QString& str)
{
	if (str.startsWith("0x"))
		return str.mid(2).toUInt(nullptr, 16);
	return str.toUInt();
}


uint64_t HexOrDecimalQStringToUint64(const QString& str)
{
	if (str.startsWith("0x"))
		return str.mid(2).toULongLong(nullptr, 16);
	return str.toULongLong();
}


void BaseAddressDetectionThread::run()
{
	BaseAddressDetectionQtResults results;
	uint32_t alignment = HexOrDecimalQStringToUint32(m_inputs->AlignmentLineEdit->text());
	if (alignment == 0)
	{
		results.Status = "Invalid alignment value";
		emit ResultReady(results);
		return;
	}

	uint32_t minStrlen = HexOrDecimalQStringToUint32(m_inputs->StrlenLineEdit->text());
	if (minStrlen == 0)
	{
		results.Status = "Invalid minimum string length";
		emit ResultReady(results);
		return;
	}

	uint64_t upperBoundary = HexOrDecimalQStringToUint64(m_inputs->UpperBoundary->text());
	if (upperBoundary == 0)
	{
		results.Status = "Invalid upper boundary address";
		emit ResultReady(results);
		return;
	}

	uint64_t lowerBoundary = HexOrDecimalQStringToUint64(m_inputs->LowerBoundary->text());
	if (lowerBoundary >= upperBoundary)
	{
		results.Status = "Upper boundary address is less than lower";
		emit ResultReady(results);
		return;
	}

	uint32_t maxPointersPerCluster = HexOrDecimalQStringToUint32(m_inputs->MaxPointersPerCluster->text());
	if (maxPointersPerCluster < 2)
	{
		results.Status = "Invalid max pointers (must be >= 2)";
		emit ResultReady(results);
		return;
	}

	BNBaseAddressDetectionPOISetting poiSetting = BaseAddressDetectionPOISettingFromString(
		m_inputs->POIBox->currentText().toStdString());
	BinaryNinja::BaseAddressDetectionSettings settings = {
		m_inputs->ArchitectureBox->currentText().toStdString(),
		m_inputs->AnalysisBox->currentText().toStdString(),
		minStrlen,
		alignment,
		lowerBoundary,
		upperBoundary,
		poiSetting,
		maxPointersPerCluster,
	};

	if (!m_baseDetection->DetectBaseAddress(settings))
		emit ResultReady(results);

	auto scores = m_baseDetection->GetScores(&results.Confidence);
	results.Scores = scores;
	emit ResultReady(results);
}


void BaseAddressDetectionWidget::HandleResults(const BaseAddressDetectionQtResults& results)
{
	if (!results.Status.empty())
		m_status->setText(QString::fromStdString(results.Status));

	/* TODO
	if (results.Status.empty() && m_worker->IsAborted())
		m_status->setText("Aborted by user (Last Base: 0x" + QString::number(results.Results.LastTestedBaseAddress, 16) + ")");
	*/

	if (results.Scores.empty())
	{
		if (!m_worker->IsAborted())
			m_status->setText("Completed with no results");
		m_preferredBase->setText("Not available");
		m_confidence->setText("Not available");
	}
	else
	{
		m_rebaseButton->setEnabled(true);
		if (results.Status.empty() && !m_worker->IsAborted())
			m_status->setText("Completed with results");
		m_preferredBase->setText("0x" + QString::number(results.Scores.rbegin()->second, 16));
		m_confidence->setText(QString::fromStdString(BaseAddressDetectionConfidenceToString(results.Confidence)) +
			" (Score: " + QString::number(results.Scores.rbegin()->first) + ")");
		m_reloadBase->setText("0x" + QString::number(results.Scores.rbegin()->second, 16));
	}

	m_resultsTableWidget->clearContents();
	/* TODO
	size_t numRows = 0;
	for (auto rit = results.Results.Scores.rbegin(); rit != results.Results.Scores.rend(); rit++)
		numRows += results.Results.Reasons.at(rit->second).size();

	m_resultsTableWidget->setRowCount(numRows);
	size_t row = 0;
	for (auto rit = results.Results.Scores.rbegin(); rit != results.Results.Scores.rend(); rit++)
	{
		auto [score, baseaddr] = *rit;
		for (const auto& reason : results.Results.Reasons.at(baseaddr))
		{
			m_resultsTableWidget->setItem(row, 0, new QTableWidgetItem("0x" + QString::number(baseaddr, 16)));
			m_resultsTableWidget->setItem(row, 1, new QTableWidgetItem("0x" + QString::number(reason.Pointer, 16)));
			m_resultsTableWidget->setItem(row, 2, new QTableWidgetItem("0x" + QString::number(reason.POIOffset, 16)));
			m_resultsTableWidget->setItem(row, 3, new QTableWidgetItem(
				QString::fromStdString(BaseAddressDetectionPOITypeToString(reason.BaseAddressDetectionPOIType))));
			row++;
		}
	}
	*/

	m_detectBaseAddressButton->setEnabled(true);
	m_abortButton->setHidden(true);
}


void BaseAddressDetectionWidget::DetectBaseAddress()
{
	m_status->setText("Running...");
	m_resultsTableWidget->clearContents();
	m_preferredBase->setText("Not available");
	m_confidence->setText("Not available");
	m_detectBaseAddressButton->setEnabled(false);
	m_worker = new BaseAddressDetectionThread(&m_inputs, m_view);
	connect(m_worker, &BaseAddressDetectionThread::ResultReady, this, &BaseAddressDetectionWidget::HandleResults);
	connect(m_worker, &BaseAddressDetectionThread::finished, m_worker, &QObject::deleteLater);
	m_worker->start();
	m_abortButton->setHidden(false);
}


void BaseAddressDetectionWidget::Abort()
{
	m_worker->Abort();
	m_abortButton->setHidden(true);
}


void BaseAddressDetectionWidget::RebaseWithFullAnalysis()
{
	auto mappedView = m_view->GetFile()->GetViewOfType("Mapped");
	if (!mappedView)
		return;

	auto fileMetadata = m_view->GetFile();
	if (!fileMetadata)
		return;

	uint64_t address = HexOrDecimalQStringToUint64(m_reloadBase->text());
	if (!fileMetadata->Rebase(mappedView, address))
		return;

	BinaryNinja::Settings::Instance()->Set("analysis.mode", "full", mappedView);
	mappedView->Reanalyze();

	auto frame = ViewFrame::viewFrameForWidget(this);
	if (!frame)
		return;

	auto fileContext = frame->getFileContext();
	if (!fileContext)
		return;

	auto uiContext = UIContext::contextForWidget(this);
	if (!uiContext)
		return;

	uiContext->recreateViewFrames(fileContext);
	fileContext->refreshDataViewCache();
	auto view = frame->getCurrentViewInterface();
	if (!view)
		return;

	if (!view->navigate(address))
		m_view->Navigate(std::string("Linear:" + frame->getCurrentDataType().toStdString()), address);
}


BaseAddressDetectionWidget::BaseAddressDetectionWidget(QWidget* parent, BinaryNinja::Ref<BinaryNinja::BinaryView> bv)
{
	m_view = bv->GetParentView() ? bv->GetParentView() : bv;
	m_layout = new QGridLayout();
	int32_t row = 0;
	int32_t column = 0;

	m_layout->addWidget(new QLabel("Architecture:"), row, column, Qt::AlignLeft);
	m_inputs.ArchitectureBox = new QComboBox(this);
	auto architectures = BinaryNinja::Architecture::GetList();
	auto archItemList = QStringList();
	archItemList << "auto detect";
	for (const auto& arch : architectures)
		archItemList << QString::fromStdString(arch->GetName());
	m_inputs.ArchitectureBox->addItems(archItemList);
	m_layout->addWidget(m_inputs.ArchitectureBox, row, column + 1, Qt::AlignLeft);

	m_layout->addWidget(new QLabel("Analysis Level:"), row, column + 2, Qt::AlignLeft);
	m_inputs.AnalysisBox = new QComboBox(this);
	auto analysisItemList = QStringList() << "basic" << "controlFlow" << "full";
	m_inputs.AnalysisBox->addItems(analysisItemList);
	m_layout->addWidget(m_inputs.AnalysisBox, row++, column + 3, Qt::AlignLeft);

	m_layout->addWidget(new QLabel("Min. String Length:"), row, column, Qt::AlignLeft);
	m_inputs.StrlenLineEdit = new QLineEdit("10");
	m_layout->addWidget(m_inputs.StrlenLineEdit, row, column + 1, Qt::AlignLeft);

	m_layout->addWidget(new QLabel("Alignment:"), row, column + 2, Qt::AlignLeft);
	m_inputs.AlignmentLineEdit = new QLineEdit("1024");
	m_layout->addWidget(m_inputs.AlignmentLineEdit, row++, column + 3, Qt::AlignLeft);

	m_layout->addWidget(new QLabel("Lower Boundary:"), row, column, Qt::AlignLeft);
	m_inputs.LowerBoundary = new QLineEdit("0x0");
	m_layout->addWidget(m_inputs.LowerBoundary, row, column + 1, Qt::AlignLeft);

	m_layout->addWidget(new QLabel("Upper Boundary:"), row, column + 2, Qt::AlignLeft);
	m_inputs.UpperBoundary = new QLineEdit("0xffffffffffffffff");
	m_layout->addWidget(m_inputs.UpperBoundary, row++, column + 3, Qt::AlignLeft);

	m_layout->addWidget(new QLabel("Points Of Interest:"), row, column, Qt::AlignLeft);
	auto poiList = QStringList() << "All" << "Strings only" << "Functions only";
	m_inputs.POIBox = new QComboBox(this);
	m_inputs.POIBox->addItems(poiList);
	m_layout->addWidget(m_inputs.POIBox, row, column + 1, Qt::AlignLeft);

	m_layout->addWidget(new QLabel("Max Pointers:"), row, column + 2, Qt::AlignLeft);
	m_inputs.MaxPointersPerCluster = new QLineEdit("128");
	m_layout->addWidget(m_inputs.MaxPointersPerCluster, row++, column + 3, Qt::AlignLeft);

	m_detectBaseAddressButton = new QPushButton("Start");
	connect(m_detectBaseAddressButton, &QPushButton::clicked, this, &BaseAddressDetectionWidget::DetectBaseAddress);
	m_layout->addWidget(m_detectBaseAddressButton, row, column, Qt::AlignLeft);

	m_abortButton = new QPushButton("Abort");
	connect(m_abortButton, &QPushButton::clicked, this, &BaseAddressDetectionWidget::Abort);
	m_abortButton->setHidden(true);
	m_layout->addWidget(m_abortButton, row++, column + 1, Qt::AlignLeft);

	m_layout->addWidget(new QLabel("Status:"), row, column, Qt::AlignLeft);
	m_status = new QLabel("Not running");
	auto palette = m_status->palette();
	palette.setColor(QPalette::WindowText, getThemeColor(AlphanumericHighlightColor));
	m_status->setPalette(palette);
	m_status->setFont(getMonospaceFont(this));
	m_layout->addWidget(m_status, row++, column + 1, 1, 2,  Qt::AlignLeft);

	m_layout->addWidget(new QLabel("Preferred Base:"), row, column, Qt::AlignLeft);
	m_preferredBase = new QLabel("Not available");
	m_preferredBase->setTextInteractionFlags(Qt::TextSelectableByMouse);
	m_preferredBase->setFont(getMonospaceFont(this));
	m_preferredBase->setPalette(palette);
	m_layout->addWidget(m_preferredBase, row, column + 1, Qt::AlignLeft);

	m_layout->addWidget(new QLabel("Confidence:"), row, column + 2, Qt::AlignLeft);
	m_confidence = new QLabel("Not available");
	m_confidence->setFont(getMonospaceFont(this));
	m_confidence->setPalette(palette);
	m_layout->addWidget(m_confidence, row++, column + 3, Qt::AlignLeft);

	m_resultsTableWidget = new QTableWidget(this);
	m_resultsTableWidget->setColumnCount(4);
	QStringList header;
	header << "Base Address" << "Pointer" << "POI Offset" << "POI Type";
	m_resultsTableWidget->setHorizontalHeaderLabels(header);
	m_resultsTableWidget->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
	m_resultsTableWidget->horizontalHeader()->setStretchLastSection(true);
	m_resultsTableWidget->verticalHeader()->setVisible(false);
	m_resultsTableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
	m_resultsTableWidget->setSelectionBehavior(QAbstractItemView::SelectItems);
	m_resultsTableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
	m_resultsTableWidget->setMinimumHeight(150);
	m_layout->addWidget(m_resultsTableWidget, row++, column, 1, 4);

	m_layout->addWidget(new QLabel("Rebase At:"), row, column, Qt::AlignLeft);
	m_reloadBase = new QLineEdit("0x0");
	m_layout->addWidget(m_reloadBase, row++, column + 1, Qt::AlignLeft);

	m_rebaseButton = new QPushButton("Start Full Analysis");
	m_rebaseButton->setEnabled(false);
	connect(m_rebaseButton, &QPushButton::clicked, this, &BaseAddressDetectionWidget::RebaseWithFullAnalysis);
	m_layout->addWidget(m_rebaseButton, row, column, Qt::AlignLeft);

	m_layout->setColumnStretch(3, 1);
	setLayout(m_layout);
}