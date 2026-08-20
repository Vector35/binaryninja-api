#include "baseaddress.h"
#include <QButtonGroup>
#include <QScrollArea>
#include <QScrollBar>

using namespace std;


BNBaseAddressDetectionPOISetting BaseAddressDetectionPOISettingFromString(const string& setting)
{
	if (setting == "Strings only")
		return POIAnalysisStringsOnly;
	if (setting == "Functions only")
		return POIAnalysisFunctionsOnly;
	return POIAnalysisAll; // Default to All
}


BNBaseAddressDetectionAnalysisMode SelectedBaseAddressDetectionAnalysisMode(const BaseAddressDetectionQtInputs* inputs)
{
	if (inputs->InstructionAnalysisModeRadio->isChecked())
		return InstructionAnalysisBaseAddressDetection;
	return SamplingBaseAddressDetection; // Default to sampling
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


BaseAddressDetectionThread::BaseAddressDetectionThread(BaseAddressDetectionQtInputs* widgetInputs,
	BinaryNinja::Ref<BinaryNinja::BinaryView> bv)
{
	m_inputs = widgetInputs;
	m_view = bv;
	m_baseDetection = new BinaryNinja::BaseAddressDetection(m_view);
}


BaseAddressDetectionThread::~BaseAddressDetectionThread()
{
	if (m_baseDetection)
		delete m_baseDetection;
}


void BaseAddressDetectionThread::run()
{
	BaseAddressDetectionQtResults results;
	uint64_t value;
	string errorStr;

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
		m_view, m_inputs->AlignmentLineEdit->text().toStdString(), value, 0, errorStr))
	{
		results.Status = "Invalid alignment value (" + errorStr + ")";
		emit ResultReady(results);
		return;
	}
	uint32_t alignment = value;
	if (alignment == 0)
	{
		results.Status = "Invalid alignment value (must be > 0)";
		emit ResultReady(results);
		return;
	}

	auto analysisMode = SelectedBaseAddressDetectionAnalysisMode(m_inputs);
	bool detectionCompleted = false;
	if (analysisMode == SamplingBaseAddressDetection)
	{
		results.AnalysisMode = SamplingBaseAddressDetection;
		BinaryNinja::BaseAddressDetectionSamplingSettings settings;
		settings.Architecture = m_inputs->ArchitectureBox->currentText().toStdString();
		settings.MinStrlen = minStrlen;
		settings.LowerBoundary = lowerBoundary;
		settings.UpperBoundary = upperBoundary;
		settings.Alignment = alignment;
		detectionCompleted = m_baseDetection->DetectBaseAddressWithSampling(settings);
	}
	else
	{
		results.AnalysisMode = InstructionAnalysisBaseAddressDetection;
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
		BinaryNinja::BaseAddressDetectionInstructionAnalysisSettings settings;
		settings.Architecture = m_inputs->ArchitectureBox->currentText().toStdString();
		settings.MinStrlen = minStrlen;
		settings.LowerBoundary = lowerBoundary;
		settings.UpperBoundary = upperBoundary;
		settings.Analysis = m_inputs->AnalysisBox->currentText().toStdString();
		settings.Alignment = alignment;
		settings.POIAnalysis = poiSetting;
		settings.MaxPointersPerCluster = maxPointersPerCluster;
		detectionCompleted = m_baseDetection->DetectBaseAddressWithInstructionAnalysis(settings);
	}

	if (!detectionCompleted)
	{
		emit ResultReady(results);
		return;
	}

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


void BaseAddressDetectionWidget::GetClickedBaseAddress(const QModelIndex& index)
{
	if (index.isValid())
	{
		auto baseAddress = m_resultsTableWidget->item(index.row(), 0)->text();
		m_reloadBase->setText(baseAddress);
	}
}


void BaseAddressDetectionWidget::HandleResults(const BaseAddressDetectionQtResults& results)
{
	// Save scroll position to prevent unwanted scrolling when hiding/showing widgets
	QScrollArea* scrollArea = nullptr;
	int savedVerticalScrollPosition = 0;
	int savedHorizontalScrollPosition = 0;
	QWidget* ancestor = parentWidget();
	while (ancestor)
	{
		scrollArea = qobject_cast<QScrollArea*>(ancestor);
		if (scrollArea)
		{
			savedVerticalScrollPosition = scrollArea->verticalScrollBar()->value();
			savedHorizontalScrollPosition = scrollArea->horizontalScrollBar()->value();
			break;
		}
		ancestor = ancestor->parentWidget();
	}

	if (!results.Status.empty())
		m_status->setText(QString::fromStdString(results.Status));

	if (results.Status.empty() && m_worker->IsAborted())
		m_status->setText(QString("Aborted by user (Last Base: 0x%1)").arg(results.LastTestedBaseAddress, 0, 16));

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
		m_preferredBase->setText(QString("0x%1").arg(results.Scores.rbegin()->second, 0, 16));
		m_confidence->setText(QString("%1 (Score: %2)").arg(
			QString::fromStdString(BaseAddressDetectionConfidenceToString(results.Confidence)),
			QString::number(results.Scores.rbegin()->first)));
		m_reloadBase->setText(QString("0x%1").arg(results.Scores.rbegin()->second, 0, 16));
	}

	ConfigureResultsTable(results.AnalysisMode);
	m_resultsTableWidget->clearContents();
	m_resultsTableWidget->setRowCount(results.Scores.size());
	size_t row = 0;
	for (auto rit = results.Scores.rbegin(); rit != results.Scores.rend(); rit++)
	{
		auto [score, baseaddr] = *rit;
		size_t strHits = 0;
		size_t funcHits = 0;
		size_t dataHits = 0;
		for (const auto& reason : results.Reasons.at(baseaddr))
		{
			switch (reason.POIType)
			{
				case POIString:
					strHits++;
					break;
				case POIFunction:
					funcHits++;
					break;
				case POIDataVariable:
					dataHits++;
					break;
				default:
					break;
			}
		}

		m_resultsTableWidget->setItem(row, 0, new QTableWidgetItem(QString("0x%1").arg(baseaddr, 0, 16)));
		m_resultsTableWidget->setItem(row, 1, new QTableWidgetItem(QString::number(score)));
		if (results.AnalysisMode == InstructionAnalysisBaseAddressDetection)
		{
			m_resultsTableWidget->setItem(row, 2, new QTableWidgetItem(QString::number(strHits)));
			m_resultsTableWidget->setItem(row, 3, new QTableWidgetItem(QString::number(funcHits)));
			m_resultsTableWidget->setItem(row, 4, new QTableWidgetItem(QString::number(dataHits)));
		}
		row++;
	}

	m_abortButton->setHidden(true);
	m_startButton->setHidden(false);
	m_startButton->setEnabled(true);

	// Restore scroll position after widget visibility changes
	if (scrollArea)
	{
		scrollArea->verticalScrollBar()->setValue(savedVerticalScrollPosition);
		scrollArea->horizontalScrollBar()->setValue(savedHorizontalScrollPosition);
	}
}


void BaseAddressDetectionWidget::DetectBaseAddress()
{
	// Save scroll position to prevent unwanted scrolling when hiding/showing widgets
	QScrollArea* scrollArea = nullptr;
	int savedVerticalScrollPosition = 0;
	int savedHorizontalScrollPosition = 0;
	QWidget* ancestor = parentWidget();
	while (ancestor)
	{
		scrollArea = qobject_cast<QScrollArea*>(ancestor);
		if (scrollArea)
		{
			savedVerticalScrollPosition = scrollArea->verticalScrollBar()->value();
			savedHorizontalScrollPosition = scrollArea->horizontalScrollBar()->value();
			break;
		}
		ancestor = ancestor->parentWidget();
	}

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

	// Restore scroll position after widget visibility changes
	if (scrollArea)
	{
		scrollArea->verticalScrollBar()->setValue(savedVerticalScrollPosition);
		scrollArea->horizontalScrollBar()->setValue(savedHorizontalScrollPosition);
	}
}


void BaseAddressDetectionWidget::Abort()
{
	m_worker->Abort();
	m_abortButton->setHidden(true);
	m_startButton->setHidden(false);
	m_startButton->setEnabled(false);
}


const std::string BaseAddressDetectionWidget::GetRebaseViewName()
{
	auto fileMetadata = m_view->GetFile();
	if (!fileMetadata)
		return "";

	for (const auto& viewName : fileMetadata->GetExistingViews())
	{
		if (viewName != "Raw")
			return viewName;
	}

	return "";
}


void BaseAddressDetectionWidget::RebaseWithFullAnalysis()
{
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

	auto rebaseViewName = GetRebaseViewName();
	if (!rebaseViewName.empty())
	{
		// Found an existing view that isn't raw, rebase it
		auto view = m_view->GetFile()->GetViewOfType(rebaseViewName);
		if (!view)
			return;

		bool result = false;
		ProgressTask* task = new ProgressTask(this, "Rebase", "Rebasing...", "Cancel", [&](BinaryNinja::ProgressFunction progress) {
			result = fileMetadata->Rebase(view, address, progress);
		});
		task->wait();
		if (!result)
			return;

		view->Reanalyze();
	}
	else
	{
		// Only a raw view exists - load the binary and run full analysis
		BinaryNinja::Settings::Instance()->Set("analysis.mode", "full", m_view);
		map<string, BinaryNinja::Ref<BinaryNinja::Metadata>> metadataMap = {
			{"analysis.linearSweep.permissive", new BinaryNinja::Metadata(true)},
			{"loader.imageBase", new BinaryNinja::Metadata((uint64_t) address)},
		};

		if (m_inputs.ArchitectureBox->currentText() != "auto detect")
			metadataMap["loader.platform"] = new BinaryNinja::Metadata(m_inputs.ArchitectureBox->currentText().toStdString());

		auto options = new BinaryNinja::Metadata(metadataMap);
		auto newView = Load(m_view->GetFile()->GetViewOfType("Raw"), false, options->GetJsonString());
		if (!newView)
			return;

		rebaseViewName = newView->GetTypeName();
	}

	// Refresh the UI and jump to Linear view
	auto frame = ViewFrame::viewFrameForWidget(this);
	if (!frame)
		return;

	auto fileContext = frame->getFileContext();
	if (!fileContext)
		return;

	auto uiContext = UIContext::contextForWidget(this);
	if (!uiContext)
		return;

	fileContext->refreshDataViewCache();
	uiContext->recreateViewFrames(fileContext);
	QCoreApplication::processEvents();

	auto newFrame = fileContext->getCurrentViewFrame();
	if (!newFrame)
		return;

	newFrame->navigate(QString("Linear:%1").arg(QString::fromStdString(rebaseViewName)), address);
}


void BaseAddressDetectionWidget::CreateAdvancedSettingsGroup()
{
	int32_t row = 0;
	int32_t column = 0;
	const int32_t controlWidth = 220;
	auto grid = new QGridLayout();
	grid->setHorizontalSpacing(24);
	grid->setColumnStretch(column, 0);
	grid->setColumnStretch(column + 1, 0);
	grid->setColumnStretch(column + 2, 0);
	grid->setColumnStretch(column + 3, 0);
	grid->setColumnStretch(column + 4, 1);

	m_inputs.StrlenLabel = new QLabel("Min. String Length:");
	grid->addWidget(m_inputs.StrlenLabel, row, column, Qt::AlignLeft);
	m_inputs.StrlenLineEdit = new QLineEdit("0n10");
	m_inputs.StrlenLineEdit->setFixedWidth(controlWidth);
	grid->addWidget(m_inputs.StrlenLineEdit, row, column + 1, Qt::AlignLeft);

	m_inputs.AlignmentLabel = new QLabel("Alignment:");
	grid->addWidget(m_inputs.AlignmentLabel, row, column + 2, Qt::AlignLeft);
	m_inputs.AlignmentLineEdit = new QLineEdit("0x1000");
	m_inputs.AlignmentLineEdit->setFixedWidth(controlWidth);
	grid->addWidget(m_inputs.AlignmentLineEdit, row++, column + 3, Qt::AlignLeft);

	m_inputs.LowerBoundaryLabel = new QLabel("Lower Boundary:");
	grid->addWidget(m_inputs.LowerBoundaryLabel, row, column, Qt::AlignLeft);
	m_inputs.LowerBoundary = new QLineEdit("0x0");
	m_inputs.LowerBoundary->setFixedWidth(controlWidth);
	grid->addWidget(m_inputs.LowerBoundary, row, column + 1, Qt::AlignLeft);

	m_inputs.UpperBoundaryLabel = new QLabel("Upper Boundary:");
	grid->addWidget(m_inputs.UpperBoundaryLabel, row, column + 2, Qt::AlignLeft);
	m_inputs.UpperBoundary = new QLineEdit("0xffffffffffffffff");
	m_inputs.UpperBoundary->setFixedWidth(controlWidth);
	grid->addWidget(m_inputs.UpperBoundary, row++, column + 3, Qt::AlignLeft);

	m_inputs.POILabel = new QLabel("Points Of Interest:");
	grid->addWidget(m_inputs.POILabel, row, column, Qt::AlignLeft);
	auto poiList = QStringList() << "All" << "Strings only" << "Functions only";
	m_inputs.POIBox = new QComboBox(this);
	m_inputs.POIBox->addItems(poiList);
	m_inputs.POIBox->setFixedWidth(controlWidth);
	grid->addWidget(m_inputs.POIBox, row, column + 1, Qt::AlignLeft);

	m_inputs.MaxPointersPerClusterLabel = new QLabel("Max Pointers:");
	grid->addWidget(m_inputs.MaxPointersPerClusterLabel, row, column + 2, Qt::AlignLeft);
	m_inputs.MaxPointersPerCluster = new QLineEdit("0n128");
	m_inputs.MaxPointersPerCluster->setFixedWidth(controlWidth);
	grid->addWidget(m_inputs.MaxPointersPerCluster, row++, column + 3, Qt::AlignLeft);

	m_advancedSettingsGroup = new ExpandableGroup(grid);
	m_advancedSettingsGroup->setTitle("Advanced Settings");
}


void BaseAddressDetectionWidget::ConfigureResultsTable(BNBaseAddressDetectionAnalysisMode analysisMode)
{
	QStringList header;
	header << "Base Address" << "Score";
	if (analysisMode == InstructionAnalysisBaseAddressDetection)
		header << "String Hits" << "Function Hits" << "Data Hits";

	m_resultsTableWidget->setColumnCount(header.size());
	m_resultsTableWidget->setHorizontalHeaderLabels(header);

	if (m_detectionModeWidget)
	{
		const int tableWidth = m_detectionModeWidget->sizeHint().width();
		m_resultsTableWidget->setMinimumWidth(tableWidth);
		m_resultsTableWidget->setMaximumWidth(tableWidth);
	}
	else
	{
		m_resultsTableWidget->setMinimumWidth(0);
		m_resultsTableWidget->setMaximumWidth(QWIDGETSIZE_MAX);
	}
}


void BaseAddressDetectionWidget::UpdateModeSpecificSettingsVisibility()
{
	const bool showInstructionAnalysisSettings =
		SelectedBaseAddressDetectionAnalysisMode(&m_inputs) == InstructionAnalysisBaseAddressDetection;
	m_inputs.AnalysisLabel->setVisible(showInstructionAnalysisSettings);
	m_inputs.AnalysisBox->setVisible(showInstructionAnalysisSettings);
	m_inputs.AlignmentLabel->setVisible(true);
	m_inputs.AlignmentLineEdit->setVisible(true);
	m_inputs.POILabel->setVisible(showInstructionAnalysisSettings);
	m_inputs.POIBox->setVisible(showInstructionAnalysisSettings);
	m_inputs.MaxPointersPerClusterLabel->setVisible(showInstructionAnalysisSettings);
	m_inputs.MaxPointersPerCluster->setVisible(showInstructionAnalysisSettings);

	if (m_advancedSettingsGroup)
	{
		m_advancedSettingsGroup->setContentExpandable(false);
		m_advancedSettingsGroup->updateGeometry();
		if (m_advancedSettingsGroup->layout())
			m_advancedSettingsGroup->layout()->activate();
	}
	if (m_layout)
		m_layout->activate();
}


BaseAddressDetectionWidget::BaseAddressDetectionWidget(QWidget* parent,
	BinaryNinja::Ref<BinaryNinja::BinaryView> bv) : QWidget(parent)
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
	if (m_view->GetDefaultArchitecture())
	{
		auto currentArchIndex = m_inputs.ArchitectureBox->findText(
			QString::fromStdString(m_view->GetDefaultArchitecture()->GetName()));
		if (currentArchIndex >= 0)
			m_inputs.ArchitectureBox->setCurrentIndex(currentArchIndex);
	}
	m_layout->addWidget(m_inputs.ArchitectureBox, row++, column + 1, Qt::AlignLeft);

	m_detectionModeWidget = new QWidget(this);
	auto modeLayout = new QGridLayout();
	modeLayout->setContentsMargins(0, 0, 0, 0);
	modeLayout->setHorizontalSpacing(8);
	modeLayout->setVerticalSpacing(2);
	auto modeButtonGroup = new QButtonGroup(this);
	m_inputs.SamplingModeRadio = new QRadioButton("Sampling Mode", this);
	m_inputs.SamplingModeRadio->setChecked(true);
	m_inputs.InstructionAnalysisModeRadio = new QRadioButton("IL Analysis Mode", this);
	modeButtonGroup->addButton(m_inputs.SamplingModeRadio);
	modeButtonGroup->addButton(m_inputs.InstructionAnalysisModeRadio);

	auto samplingDescription = new QLabel(
		"Samples raw binary data and correlates global pointers with string offsets. Recommended for most binaries "
		"and typically provides the fastest results.", this);
	auto ilAnalysisDescription = new QLabel(
		"Analyzes instructions and correlates derived pointers with strings, data variables, and function starts. "
		"Recommended for binaries that contain few or no strings.", this);
	samplingDescription->setWordWrap(true);
	ilAnalysisDescription->setWordWrap(true);
	samplingDescription->setFixedWidth(620);
	ilAnalysisDescription->setFixedWidth(620);
	auto setDescriptionHeight = [](QLabel* label) {
		const auto margins = label->contentsMargins();
		const int textWidth = label->width() - margins.left() - margins.right();
		const QRect textBounds = label->fontMetrics().boundingRect(
			QRect(0, 0, textWidth, QWIDGETSIZE_MAX), Qt::TextWordWrap, label->text());
		label->setMinimumHeight(textBounds.height() + margins.top() + margins.bottom());
	};
	setDescriptionHeight(samplingDescription);
	setDescriptionHeight(ilAnalysisDescription);
	auto descriptionPalette = samplingDescription->palette();
	descriptionPalette.setColor(QPalette::WindowText, getThemeColor(AnnotationColor));
	samplingDescription->setPalette(descriptionPalette);
	ilAnalysisDescription->setPalette(descriptionPalette);
	modeLayout->addWidget(m_inputs.SamplingModeRadio, 0, 0, Qt::AlignLeft | Qt::AlignTop);
	modeLayout->addWidget(samplingDescription, 1, 0, Qt::AlignLeft | Qt::AlignTop);
	modeLayout->addWidget(m_inputs.InstructionAnalysisModeRadio, 2, 0, Qt::AlignLeft | Qt::AlignTop);
	modeLayout->addWidget(ilAnalysisDescription, 3, 0, Qt::AlignLeft | Qt::AlignTop);
	m_detectionModeWidget->setLayout(modeLayout);
	m_layout->addWidget(m_detectionModeWidget, row++, column, 1, 4, Qt::AlignLeft);

	m_inputs.AnalysisLabel = new QLabel("Analysis Level:");
	m_layout->addWidget(m_inputs.AnalysisLabel, row, column, Qt::AlignLeft);
	m_inputs.AnalysisBox = new QComboBox(this);
	auto analysisItemList = QStringList() << "full" << "basic" << "controlFlow";
	m_inputs.AnalysisBox->addItems(analysisItemList);
	m_layout->addWidget(m_inputs.AnalysisBox, row++, column + 1, Qt::AlignLeft);
	connect(m_inputs.SamplingModeRadio, &QRadioButton::toggled,
		this, &BaseAddressDetectionWidget::UpdateModeSpecificSettingsVisibility);
	connect(m_inputs.InstructionAnalysisModeRadio, &QRadioButton::toggled,
		this, &BaseAddressDetectionWidget::UpdateModeSpecificSettingsVisibility);

	CreateAdvancedSettingsGroup();
	m_layout->addWidget(m_advancedSettingsGroup, row++, column, 1, 4);
	UpdateModeSpecificSettingsVisibility();

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
	ConfigureResultsTable(SamplingBaseAddressDetection);
	m_resultsTableWidget->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
	m_resultsTableWidget->horizontalHeader()->setStretchLastSection(true);
	m_resultsTableWidget->verticalHeader()->setVisible(false);
	m_resultsTableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
	m_resultsTableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_resultsTableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
	m_resultsTableWidget->setMinimumHeight(150);
	m_layout->addWidget(m_resultsTableWidget, row++, column, 1, 5);
	connect(m_resultsTableWidget, &QTableWidget::clicked, this, &BaseAddressDetectionWidget::GetClickedBaseAddress);

	m_reloadBase = new QLineEdit("0x0");
	m_layout->addWidget(m_reloadBase, row, column, Qt::AlignLeft);

	m_rebaseButton = new QPushButton("Start Full Analysis");
	connect(m_rebaseButton, &QPushButton::clicked, this, &BaseAddressDetectionWidget::RebaseWithFullAnalysis);
	m_layout->addWidget(m_rebaseButton, row, column + 1, Qt::AlignLeft);

	HideResultsWidgets(true);
	m_layout->setColumnStretch(3, 1);
	setLayout(m_layout);
}
