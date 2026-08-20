#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <algorithm>
#include <vector>
#include "sections.h"
#include "headers.h"
#include "fontsettings.h"


SectionsModel::SectionsModel(QObject* parent, BinaryViewRef data) : QObject(parent), BinaryDataNotification(SectionUpdates)
{
	m_data = data;
	m_data->RegisterNotification(this);
	updateSections();
}


SectionsModel::~SectionsModel()
{
	m_data->UnregisterNotification(this);
}


void SectionsModel::updateSections()
{
	m_sections.clear();
	for (auto& section : m_data->GetSections())
		if (section->GetSemantics() != ExternalSectionSemantics)
			m_sections.push_back(section);
	sort(m_sections.begin(), m_sections.end(),
	    [&](SectionRef a, SectionRef b) { return a->GetStart() < b->GetStart(); });

	emit sectionsChanged();
}


void SectionsModel::OnSectionAdded(BinaryNinja::BinaryView* data, BinaryNinja::Section* section)
{
	QMetaObject::invokeMethod(this, &SectionsModel::updateSections, Qt::QueuedConnection);
}


void SectionsModel::OnSectionRemoved(BinaryNinja::BinaryView* data, BinaryNinja::Section* section)
{
	QMetaObject::invokeMethod(this, &SectionsModel::updateSections, Qt::QueuedConnection);
}


void SectionsModel::OnSectionUpdated(BinaryNinja::BinaryView* data, BinaryNinja::Section* section)
{
	QMetaObject::invokeMethod(this, &SectionsModel::updateSections, Qt::QueuedConnection);
}


SegmentsWidget::SegmentsWidget(QWidget* parent, BinaryViewRef data) : QWidget(parent)
{
	QGridLayout* layout = new QGridLayout();
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setVerticalSpacing(1);
	layout->setHorizontalSpacing(UIContext::getScaledWindowSize(16, 16).width());

	for (auto& segment : data->GetSegments())
		if ((segment->GetFlags() & (SegmentReadable | SegmentWritable | SegmentExecutable)) != 0)
			m_segments.push_back(segment);
	sort(m_segments.begin(), m_segments.end(),
	    [&](SegmentRef a, SegmentRef b) { return a->GetStart() < b->GetStart(); });

	int row = 0;
	for (auto& segment : m_segments)
	{
		QString begin = QString("0x") + QString::number(segment->GetStart(), 16);
		QString end = QString("0x") + QString::number(segment->GetEnd(), 16);

		QString permissions;
		if (segment->GetFlags() & SegmentReadable)
			permissions += "r";
		else
			permissions += "-";
		if (segment->GetFlags() & SegmentWritable)
			permissions += "w";
		else
			permissions += "-";
		if (segment->GetFlags() & SegmentExecutable)
			permissions += "x";
		else
			permissions += "-";

		QHBoxLayout* rangeLayout = new QHBoxLayout();
		rangeLayout->setContentsMargins(0, 0, 0, 0);
		NavigationAddressLabel* beginLabel = new NavigationAddressLabel(begin);
		QLabel* dashLabel = new QLabel("-");
		dashLabel->setFont(getMonospaceFont(this));
		NavigationAddressLabel* endLabel = new NavigationAddressLabel(end);
		rangeLayout->addWidget(beginLabel);
		rangeLayout->addWidget(dashLabel);
		rangeLayout->addWidget(endLabel);
		layout->addLayout(rangeLayout, row, 0);

		QLabel* permissionsLabel = new QLabel(permissions);
		permissionsLabel->setFont(getMonospaceFont(this));
		layout->addWidget(permissionsLabel, row, 1);

		row++;
	}

	layout->setColumnStretch(2, 1);
	setLayout(layout);
}


SectionsWidget::SectionsWidget(QWidget* parent, BinaryViewRef data) : QWidget(parent), m_data(data), m_model(nullptr), m_layout(nullptr), m_isRebuilding(false)
{
	m_model = new SectionsModel(this, data);

	m_layout = new QGridLayout();
	m_layout->setContentsMargins(0, 0, 0, 0);
	m_layout->setVerticalSpacing(1);
	m_layout->setHorizontalSpacing(UIContext::getScaledWindowSize(16, 16).width());
	setLayout(m_layout);

	connect(m_model, &SectionsModel::sectionsChanged, this, &SectionsWidget::rebuildLayout, Qt::QueuedConnection);

	rebuildLayout();
}


SectionsWidget::~SectionsWidget()
{
	if (m_model)
	{
		disconnect(m_model, nullptr, this, nullptr);
		m_model->blockSignals(true);
	}
}


void SectionsWidget::rebuildLayout()
{
	if (m_isRebuilding)
		return;

	m_isRebuilding = true;
	setUpdatesEnabled(false);

	QObjectList children = this->children();
	for (QObject* child : children)
	{
		if (QWidget* widget = qobject_cast<QWidget*>(child))
			delete widget;
	}

	delete m_layout;

	m_layout = new QGridLayout();
	m_layout->setContentsMargins(0, 0, 0, 0);
	m_layout->setVerticalSpacing(1);
	m_layout->setHorizontalSpacing(UIContext::getScaledWindowSize(16, 16).width());
	setLayout(m_layout);

	auto sections = m_model->GetSections();

	if (sections.empty())
	{
		setUpdatesEnabled(true);
		m_isRebuilding = false;
		return;
	}

	size_t maxNameLen = 0;
	for (auto& section : sections)
	{
		if (section->GetName().size() > maxNameLen)
			maxNameLen = section->GetName().size();
	}
	if (maxNameLen > 32)
		maxNameLen = 32;

	int row = 0;
	for (auto& section : sections)
	{

		std::string name = section->GetName();
		if (name.size() > maxNameLen)
			name = name.substr(0, maxNameLen - 1) + std::string("…");

		QString begin = QString("0x") + QString::number(section->GetStart(), 16);
		QString end = QString("0x") + QString::number(section->GetStart() + section->GetLength(), 16);
		QString typeName = QString::fromStdString(section->GetType());

		QString permissions;
		if (m_data->IsOffsetReadable(section->GetStart()))
			permissions += "r";
		else
			permissions += "-";
		if (m_data->IsOffsetWritable(section->GetStart()))
			permissions += "w";
		else
			permissions += "-";
		if (m_data->IsOffsetExecutable(section->GetStart()))
			permissions += "x";
		else
			permissions += "-";

		QString semantics;
		if (section->GetSemantics() == ReadOnlyCodeSectionSemantics)
			semantics = "Code";
		else if (section->GetSemantics() == ReadOnlyDataSectionSemantics)
			semantics = "Read-only Data";
		else if (section->GetSemantics() == ReadWriteDataSectionSemantics)
			semantics = "Writable Data";

		QLabel* nameLabel = new QLabel(QString::fromStdString(name));
		nameLabel->setFont(getMonospaceFont(this));
		m_layout->addWidget(nameLabel, row, 0);

		QHBoxLayout* rangeLayout = new QHBoxLayout();
		rangeLayout->setContentsMargins(0, 0, 0, 0);
		NavigationAddressLabel* beginLabel = new NavigationAddressLabel(begin);
		QLabel* dashLabel = new QLabel("-");
		dashLabel->setFont(getMonospaceFont(this));
		NavigationAddressLabel* endLabel = new NavigationAddressLabel(end);
		rangeLayout->addWidget(beginLabel);
		rangeLayout->addWidget(dashLabel);
		rangeLayout->addWidget(endLabel);
		m_layout->addLayout(rangeLayout, row, 1);

		QLabel* permissionsLabel = new QLabel(permissions);
		permissionsLabel->setFont(getMonospaceFont(this));
		m_layout->addWidget(permissionsLabel, row, 2);
		QLabel* typeLabel = new QLabel(typeName);
		typeLabel->setFont(getMonospaceFont(this));
		m_layout->addWidget(typeLabel, row, 3);
		QLabel* semanticsLabel = new QLabel(semantics);
		semanticsLabel->setFont(getMonospaceFont(this));
		m_layout->addWidget(semanticsLabel, row, 4);

		row++;
	}

	m_layout->setColumnStretch(5, 1);

	setUpdatesEnabled(true);
	m_isRebuilding = false;
}
