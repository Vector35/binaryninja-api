#include "baseaddress.h"

using namespace std;


BNBaseAddressDetectionPOISetting BaseAddressDetectionPOISettingFromString(const string& setting)
{
	if (setting == "Strings only")
		return POIAnalysisStringsOnly;
	if (setting == "Functions only")
		return POIAnalysisFunctionsOnly;
	return POIAnalysisAll; // Default to All
}


string BaseAddressDetectionPOITypeToString(BNBaseAddressDetectionPOIType type)
{
	switch (type)
	{
		case POIString:
			return "String";
		case POIFunction:
			return "Function";
		case POIDataVariable:
			return "Data variable";
		case POIFileEnd:
			return "File end";
		case POIFileStart:
			return "File start";
		default:
			return "Unknown";
	}
}


string BaseAddressDetectionConfidenceToString(BNBaseAddressDetectionConfidence level)
{
	switch (level)
	{
		case NoConfidence:
			return "Unassigned";
		case HighConfidence:
			return "High";
		case LowConfidence:
			return "Low";
		default:
			return "Unknown";
	}
}


void BaseAddressDetectionThread::run()
{
	BaseAddressDetectionQtResults results;
	uint64_t value;
	string errorStr;

	if (!BinaryNinja::BinaryView::ParseExpression(
		m_view, m_inputs->AlignmentLineEdit->text().toStdString(), value, 0, errorStr))
	{
		results.Status = "Invalid alignment value (" + errorStr + ")";
		emit ResultReady(results);
		return;
	}
	uint32_t alignment = value;

	if (!BinaryNinja::BinaryView::ParseExpression(
		m_view, m_inputs->StrlenLineEdit->text().toStdString(), value, 0, errorStr))
	{
		results.Status = "Invalid minimum string length (" + errorStr + ")";
		emit ResultReady(results);
		return;
	}
	uint32_t minStrlen = value;

	uint64_t upperBoundary;
	if (!BinaryNinja::BinaryView::ParseExpression(
		m_view, m_inputs->UpperBoundary->text().toStdString(), upperBoundary, 0, errorStr))
	{
		results.Status = "Invalid upper boundary address (" + errorStr + ")";
		emit ResultReady(results);
		return;
	}

	uint64_t lowerBoundary;
	if (!BinaryNinja::BinaryView::ParseExpression(
		m_view, m_inputs->LowerBoundary->text().toStdString(), lowerBoundary, 0, errorStr))
	{
		results.Status = "Invalid lower boundary address (" + errorStr + ")";
		emit ResultReady(results);
		return;
	}

	if (lowerBoundary >= upperBoundary)
	{
		results.Status = "Upper boundary address is less than lower";
		emit ResultReady(results);
		return;
	}

	if (!BinaryNinja::BinaryView::ParseExpression(
		m_view, m_inputs->MaxPointersPerCluster->text().toStdString(), value, 0, errorStr))
	{
		results.Status = "Invalid max pointers (" + errorStr + ")";
		emit ResultReady(results);
		return;
	}

	uint32_t maxPointersPerCluster = value;
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

	auto scores = m_baseDetection->GetScores(&results.Confidence, &results.LastTestedBaseAddress);
	results.Scores = scores;
	for (const auto& score : scores)
	{
		auto reasons = m_baseDetection->GetReasonsForBaseAddress(score.second);
		results.Reasons[score.second] = reasons;
	}

	emit ResultReady(results);
}


void BaseAddressDetectionWidget::HideResultsWidgets(bool hide)
{
	if (hide)
	{
		m_preferredBaseLabel->setHidden(true);
		m_preferredBase->setHidden(true);
		m_confidenceLabel->setHidden(true);
		m_confidence->setHidden(true);
		m_resultsTableWidget->setHidden(true);
		m_reloadBase->setHidden(true);
		m_rebaseButton->setHidden(true);
	}
	else
	{
		m_preferredBaseLabel->setHidden(false);
		m_preferredBase->setHidden(false);
		m_confidenceLabel->setHidden(false);
		m_confidence->setHidden(false);
		m_resultsTableWidget->setHidden(false);
		m_reloadBase->setHidden(false);
		m_rebaseButton->setHidden(false);
	}
}


void BaseAddressDetectionWidget::HandleResults(const BaseAddressDetectionQtResults& results)
{
	if (!results.Status.empty())
		m_status->setText(QString::fromStdString(results.Status));

	if (results.Status.empty() && m_worker->IsAborted())
		m_status->setText(QString("Aborted by user (Last Base: 0x%1)").arg(
			QString::number(results.LastTestedBaseAddress, 16)));

	if (results.Scores.empty())
	{
		if (!m_worker->IsAborted() && results.Status.empty())
			m_status->setText("Completed with no results");
		m_preferredBase->setText("Not available");
		m_confidence->setText("Not available");
	}
	else
	{
		HideResultsWidgets(false);
		if (results.Status.empty() && !m_worker->IsAborted())
			m_status->setText("Completed with results");
		m_preferredBase->setText(QString("0x%1").arg(QString::number(results.Scores.rbegin()->second, 16)));
		m_confidence->setText(QString("%1 (Score: %2)").arg(
			QString::fromStdString(BaseAddressDetectionConfidenceToString(results.Confidence)),
			QString::number(results.Scores.rbegin()->first)));
		m_reloadBase->setText(QString("0x%1").arg(QString::number(results.Scores.rbegin()->second, 16)));
	}

	m_resultsTableWidget->clearContents();
	size_t numRows = 0;
	for (auto rit = results.Scores.rbegin(); rit != results.Scores.rend(); rit++)
		numRows += results.Reasons.at(rit->second).size();

	m_resultsTableWidget->setRowCount(numRows);
	size_t row = 0;
	for (auto rit = results.Scores.rbegin(); rit != results.Scores.rend(); rit++)
	{
		auto [score, baseaddr] = *rit;
		for (const auto& reason : results.Reasons.at(baseaddr))
		{
			m_resultsTableWidget->setItem(row, 0,
				new QTableWidgetItem(QString("0x%1").arg(QString::number(baseaddr, 16))));
			m_resultsTableWidget->setItem(row, 1, new QTableWidgetItem(
				QString("0x%1").arg(QString::number(reason.Pointer, 16))));
			m_resultsTableWidget->setItem(row, 2, new QTableWidgetItem(
				QString("0x%1").arg(QString::number(reason.POIOffset, 16))));
			m_resultsTableWidget->setItem(row, 3, new QTableWidgetItem(
				QString::fromStdString(BaseAddressDetectionPOITypeToString(reason.POIType))));
			row++;
		}
	}

	m_abortButton->setHidden(true);
	m_startButton->setHidden(false);
	m_startButton->setEnabled(true);
}


void BaseAddressDetectionWidget::DetectBaseAddress()
{
	HideResultsWidgets(true);
	m_status->setText("Running...");
	m_resultsTableWidget->clearContents();
	m_preferredBase->setText("Not available");
	m_confidence->setText("Not available");
	m_startButton->setHidden(true);
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
	m_startButton->setHidden(false);
	m_startButton->setEnabled(false);
}


void BaseAddressDetectionWidget::RebaseWithFullAnalysis()
{
	auto mappedView = m_view->GetFile()->GetViewOfType("Mapped");
	if (!mappedView)
		return;

	auto fileMetadata = m_view->GetFile();
	if (!fileMetadata)
		return;

	uint64_t address;
	string errorStr;
	if (!BinaryNinja::BinaryView::ParseExpression(m_view, m_reloadBase->text().toStdString(), address, 0, errorStr))
	{
		m_status->setText(QString("Invalid rebase address (%1)").arg(QString::fromStdString(errorStr)));
		return;
	}

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
		m_view->Navigate(string("Linear:" + frame->getCurrentDataType().toStdString()), address);
}


void BaseAddressDetectionWidget::CreateAdvancedSettingsGroup()
{
	int32_t row = 0;
	int32_t column = 0;
	auto grid = new QGridLayout();

	grid->addWidget(new QLabel("Min. String Length:"), row, column, Qt::AlignLeft);
	m_inputs.StrlenLineEdit = new QLineEdit("0n10");
	grid->addWidget(m_inputs.StrlenLineEdit, row, column + 1, Qt::AlignLeft);

	grid->addWidget(new QLabel("Alignment:"), row, column + 2, Qt::AlignLeft);
	m_inputs.AlignmentLineEdit = new QLineEdit("0n1024");
	grid->addWidget(m_inputs.AlignmentLineEdit, row++, column + 3, Qt::AlignLeft);

	grid->addWidget(new QLabel("Lower Boundary:"), row, column, Qt::AlignLeft);
	m_inputs.LowerBoundary = new QLineEdit("0x0");
	grid->addWidget(m_inputs.LowerBoundary, row, column + 1, Qt::AlignLeft);

	grid->addWidget(new QLabel("Upper Boundary:"), row, column + 2, Qt::AlignLeft);
	m_inputs.UpperBoundary = new QLineEdit("0xffffffffffffffff");
	grid->addWidget(m_inputs.UpperBoundary, row++, column + 3, Qt::AlignLeft);

	grid->addWidget(new QLabel("Points Of Interest:"), row, column, Qt::AlignLeft);
	auto poiList = QStringList() << "All" << "Strings only" << "Functions only";
	m_inputs.POIBox = new QComboBox(this);
	m_inputs.POIBox->addItems(poiList);
	grid->addWidget(m_inputs.POIBox, row, column + 1, Qt::AlignLeft);

	grid->addWidget(new QLabel("Max Pointers:"), row, column + 2, Qt::AlignLeft);
	m_inputs.MaxPointersPerCluster = new QLineEdit("0n128");
	grid->addWidget(m_inputs.MaxPointersPerCluster, row++, column + 3, Qt::AlignLeft);

	m_advancedSettingsGroup = new ExpandableGroup(grid);
	m_advancedSettingsGroup->setTitle("Advanced Settings");
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
	m_layout->addWidget(m_inputs.ArchitectureBox, row++, column + 1, Qt::AlignLeft);

	m_layout->addWidget(new QLabel("Analysis Level:"), row, column, Qt::AlignLeft);
	m_inputs.AnalysisBox = new QComboBox(this);
	auto analysisItemList = QStringList() << "basic" << "controlFlow" << "full";
	m_inputs.AnalysisBox->addItems(analysisItemList);
	m_layout->addWidget(m_inputs.AnalysisBox, row++, column + 1, Qt::AlignLeft);

	CreateAdvancedSettingsGroup();
	m_layout->addWidget(m_advancedSettingsGroup, row++, column, 1, 4);

	m_startButton = new QPushButton("Start");
	connect(m_startButton, &QPushButton::clicked, this, &BaseAddressDetectionWidget::DetectBaseAddress);
	m_layout->addWidget(m_startButton, row, column, Qt::AlignLeft);

	m_abortButton = new QPushButton("Abort");
	connect(m_abortButton, &QPushButton::clicked, this, &BaseAddressDetectionWidget::Abort);
	m_abortButton->setHidden(true);
	m_layout->addWidget(m_abortButton, row, column, Qt::AlignLeft);

	m_status = new QLabel("Not running");
	auto palette = m_status->palette();
	palette.setColor(QPalette::WindowText, getThemeColor(AlphanumericHighlightColor));
	m_status->setPalette(palette);
	m_status->setFont(getMonospaceFont(this));
	m_layout->addWidget(m_status, row++, column + 1, 1, 2, Qt::AlignLeft);

	m_preferredBaseLabel = new QLabel("Preferred Base:");
	m_layout->addWidget(m_preferredBaseLabel, row, column, Qt::AlignLeft);
	m_preferredBase = new QLabel("Not available");
	m_preferredBase->setTextInteractionFlags(Qt::TextSelectableByMouse);
	m_preferredBase->setFont(getMonospaceFont(this));
	m_preferredBase->setPalette(palette);
	m_layout->addWidget(m_preferredBase, row, column + 1, Qt::AlignLeft);

	m_confidenceLabel = new QLabel("Confidence:");
	m_layout->addWidget(m_confidenceLabel, row, column + 2, Qt::AlignLeft);
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

	m_reloadBase = new QLineEdit("0x0");
	m_layout->addWidget(m_reloadBase, row, column, Qt::AlignLeft);

	m_rebaseButton = new QPushButton("Start Full Analysis");
	connect(m_rebaseButton, &QPushButton::clicked, this, &BaseAddressDetectionWidget::RebaseWithFullAnalysis);
	m_layout->addWidget(m_rebaseButton, row, column + 1, Qt::AlignLeft);

	HideResultsWidgets(true);
	m_layout->setColumnStretch(3, 1);
	setLayout(m_layout);
}