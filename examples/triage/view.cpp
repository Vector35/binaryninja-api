#include <QtWidgets/QGroupBox>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QSplitter>
#include "view.h"
#include "entropy.h"
#include "entry.h"
#include "imports.h"
#include "exports.h"
#include "sections.h"
#include "fileinfo.h"
#include "librariesinfo.h"
#include "headers.h"
#include "strings.h"
#include "baseaddress.h"
#include "fontsettings.h"
#include "analysisinfo.h"
#include <binaryninjacore.h>

TriageView::TriageView(QWidget* parent, BinaryViewRef data) : QScrollArea(parent)
{
	setBinaryDataNavigable(true);
	setupView(this);
	m_data = data;
	m_currentOffset = m_data->GetEntryPoint();

	QWidget* container = new QWidget(this);
	QVBoxLayout* layout = new QVBoxLayout();

	QGroupBox* entropyGroup = new QGroupBox("Entropy", container);
	QVBoxLayout* entropyLayout = new QVBoxLayout();
	entropyLayout->addWidget(new EntropyWidget(entropyGroup, this, m_data));
	entropyGroup->setLayout(entropyLayout);
	layout->addWidget(entropyGroup);

	QGroupBox* fileInfoGroup = new QGroupBox("File Info", container);
	QVBoxLayout* fileInfoLayout = new QVBoxLayout();
	fileInfoLayout->addWidget(new FileInfoWidget(fileInfoGroup, m_data));
	fileInfoGroup->setLayout(fileInfoLayout);
	layout->addWidget(fileInfoGroup);

	Headers* hdr = nullptr;
	if (m_data->GetTypeName() == "PE")
		hdr = new PEHeaders(m_data);
	else if (m_data->GetTypeName() != "Raw")
		hdr = new GenericHeaders(m_data);

	if (hdr)
	{
		QGroupBox* headerGroup = new QGroupBox("Headers", container);
		QVBoxLayout* headerLayout = new QVBoxLayout();
		HeaderWidget* headerWidget = new HeaderWidget(headerGroup, *hdr);
		headerLayout->addWidget(headerWidget);
		headerGroup->setLayout(headerLayout);
		layout->addWidget(headerGroup);
		delete hdr;
	}

	auto fileMetadata = m_data->GetFile();
	if (m_data == fileMetadata->GetViewOfType("Raw") || m_data == fileMetadata->GetViewOfType("Mapped"))
	{
		QGroupBox* baseDetectionGroup = new QGroupBox("Base Address Detection", container);
		QVBoxLayout* baseDetectionLayout = new QVBoxLayout();
		baseDetectionLayout->addWidget(new BaseAddressDetectionWidget(this, data));
		baseDetectionGroup->setLayout(baseDetectionLayout);
		layout->addWidget(baseDetectionGroup);
	}

	QGroupBox* librariesGroup = new QGroupBox("Libraries", container);
	QVBoxLayout* librariesLayout = new QVBoxLayout();
	librariesLayout->addWidget(new LibrariesWidget(this, data));
	librariesGroup->setLayout(librariesLayout);
	layout->addWidget(librariesGroup);

	if (m_data->IsExecutable())
	{
		QSplitter* importExportSplitter = new QSplitter(Qt::Horizontal);

		QGroupBox* importGroup = new QGroupBox("Imports", container);
		QVBoxLayout* importLayout = new QVBoxLayout();
		importLayout->addWidget(new ImportsWidget(importGroup, this, m_data));
		importGroup->setLayout(importLayout);
		importExportSplitter->addWidget(importGroup);

		QSplitter* exportEntrySplitter = new QSplitter(Qt::Vertical);

		QGroupBox* exportGroup = new QGroupBox("Exports", container);
		QVBoxLayout* exportLayout = new QVBoxLayout();
		exportLayout->addWidget(new ExportsWidget(exportGroup, this, m_data));
		exportGroup->setLayout(exportLayout);
		exportEntrySplitter->addWidget(exportGroup);

		QGroupBox* entryGroup = new QGroupBox("Entry Functions", container);
		QVBoxLayout* entryLayout = new QVBoxLayout();
		entryLayout->addWidget(new EntryWidget(entryGroup, this, m_data));
		entryGroup->setLayout(entryLayout);
		exportEntrySplitter->addWidget(entryGroup);

		importExportSplitter->addWidget(exportEntrySplitter);
		layout->addWidget(importExportSplitter);

		if (m_data->GetTypeName() != "PE")
		{
			QGroupBox* segmentsGroup = new QGroupBox("Segments", container);
			QVBoxLayout* segmentsLayout = new QVBoxLayout();
			SegmentsWidget* segmentsWidget = new SegmentsWidget(segmentsGroup, m_data);
			segmentsLayout->addWidget(segmentsWidget);
			segmentsGroup->setLayout(segmentsLayout);
			layout->addWidget(segmentsGroup);
			if (segmentsWidget->GetSegments().size() == 0)
				segmentsGroup->hide();
		}

		QGroupBox* sectionsGroup = new QGroupBox("Sections", container);
		QVBoxLayout* sectionsLayout = new QVBoxLayout();
		SectionsWidget* sectionsWidget = new SectionsWidget(sectionsGroup, m_data);
		sectionsLayout->addWidget(sectionsWidget);
		sectionsGroup->setLayout(sectionsLayout);
		layout->addWidget(sectionsGroup);
		if (sectionsWidget->GetSections().size() == 0)
			sectionsGroup->hide();

		QGroupBox* analysisInfoGroup = new QGroupBox("Analysis Info", container);
		QVBoxLayout* analysisInfoLayout = new QVBoxLayout();
		analysisInfoLayout->addWidget(new AnalysisInfoWidget(analysisInfoGroup, m_data));
		analysisInfoGroup->setLayout(analysisInfoLayout);
		layout->addWidget(analysisInfoGroup);

		QGroupBox* stringsGroup = new QGroupBox("Strings", container);
		QVBoxLayout* stringsLayout = new QVBoxLayout();
		stringsLayout->addWidget(new StringsWidget(stringsGroup, this, m_data));
		stringsGroup->setLayout(stringsLayout);
		layout->addWidget(stringsGroup);

		QHBoxLayout* buttonLayout = new QHBoxLayout();
		buttonLayout->addStretch(1);
		m_fullAnalysisButton = new QPushButton("Start Full Analysis");
		connect(m_fullAnalysisButton, &QPushButton::clicked, this, &TriageView::startFullAnalysis);
		buttonLayout->addWidget(m_fullAnalysisButton);
		layout->addLayout(buttonLayout);
		layout->addStretch(1);
	}
	else
	{
		m_byteView = new ByteView(this, m_data);
		layout->addWidget(m_byteView, 1);
	}

	container->setLayout(layout);
	setWidgetResizable(true);
	setWidget(container);

	if (m_fullAnalysisButton && (BinaryNinja::Settings::Instance()->Get<std::string>("analysis.mode", data) == "full"))
		m_fullAnalysisButton->hide();
}


BinaryViewRef TriageView::getData()
{
	return m_data;
}


uint64_t TriageView::getCurrentOffset()
{
	if (m_byteView)
		return m_byteView->getCurrentOffset();
	return m_currentOffset;
}


BNAddressRange TriageView::getSelectionOffsets()
{
	if (m_byteView)
		return m_byteView->getSelectionOffsets();
	return {m_currentOffset, m_currentOffset};
}

void TriageView::setSelectionOffsets(BNAddressRange range)
{
	// for subclass of View who does not have a meaningful setSelectionOffsets() behavior,
	// we navigate to the start of the selection range
	navigate(range.start);
}

void TriageView::setCurrentOffset(uint64_t offset)
{
	m_currentOffset = offset;
	UIContext::updateStatus();
	updateCrossReferenceSelection();
}


QFont TriageView::getFont()
{
	return getMonospaceFont(this);
}


bool TriageView::navigate(uint64_t addr)
{
	if (m_byteView)
		return m_byteView->navigate(addr);
	return false;
}


void TriageView::startFullAnalysis()
{
	BinaryNinja::Settings::Instance()->Set("analysis.mode", "full", m_data);
	for (auto& f : m_data->GetAnalysisFunctionList())
	{
		if (f->IsAnalysisSkipped())
			f->Reanalyze();
	}
	m_data->UpdateAnalysis();
	m_fullAnalysisButton->hide();
}


void TriageView::navigateToFileOffset(uint64_t offset)
{
	if (!m_byteView)
	{
		uint64_t addr = 0;
		bool hasAddr = m_data->GetAddressForDataOffset(offset, addr);
		ViewFrame* frame = ViewFrame::viewFrameForWidget(this);
		if (!frame)
			return;
		if (!hasAddr)
			frame->navigate("Hex:Raw", offset);
		else if (BinaryNinja::Settings::Instance()->Get<bool>("ui.view.graph.preferred") &&
			frame->getCurrentBinaryView() &&
			frame->getCurrentBinaryView()->GetAnalysisFunctionsForAddress(offset).size() > 0)
		{
			frame->navigate("Graph:" + frame->getCurrentDataType(), offset);
		}
		else
		{
			frame->navigate("Linear:" + frame->getCurrentDataType(), offset);
		}
	}
	else
	{
		uint64_t addr;
		bool hasAddr;
		if (m_data == m_data->GetFile()->GetViewOfType("Raw"))
		{
			addr = offset;
			hasAddr = true;
		}
		else
		{
			hasAddr = m_data->GetAddressForDataOffset(offset, addr);
		}
		if (!hasAddr)
		{
			ViewFrame* frame = ViewFrame::viewFrameForWidget(this);
			if (frame)
				frame->navigate("Hex:Raw", offset);
		}
		else
		{
			m_byteView->navigate(addr);
			m_byteView->setFocus(Qt::OtherFocusReason);
		}
	}
}


void TriageView::focusInEvent(QFocusEvent*)
{
	if (m_byteView)
		m_byteView->setFocus(Qt::OtherFocusReason);
}


TriageViewType::TriageViewType() : ViewType("Triage", "Triage Summary") {}


int TriageViewType::getPriority(BinaryViewRef data, const QString&)
{
	BinaryNinja::Ref<BinaryNinja::Settings> settings = BinaryNinja::Settings::Instance();
	auto analysisMode = settings->Get<std::string>("analysis.mode", data);
	bool full = analysisMode == "full";
	bool intermediate = analysisMode == "intermediate";
	bool alwaysPrefer = settings->Get<bool>("triage.preferSummaryView", data);
	bool preferForRaw = settings->Get<bool>("triage.preferSummaryViewForRaw", data);
	if (data->IsExecutable() && (alwaysPrefer || (!full && !intermediate)))
		return 100;
	if (data->GetLength() > 0)
	{
		if (alwaysPrefer || data->IsExecutable() || preferForRaw)
			return 25;
		return 1;
	}
	return 0;
}


QWidget* TriageViewType::create(BinaryViewRef data, ViewFrame* frame)
{
	return new TriageView(frame, data);
}
