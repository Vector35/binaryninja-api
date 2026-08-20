#pragma once

#include <QtWidgets/QWidget>
#include "uitypes.h"


class SegmentsWidget : public QWidget
{
	std::vector<SegmentRef> m_segments;

  public:
	SegmentsWidget(QWidget* parent, BinaryViewRef data);
	const std::vector<SegmentRef>& GetSegments() const { return m_segments; }
};


class SectionsModel : public QObject, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

	BinaryViewRef m_data;
	std::vector<SectionRef> m_sections;

	void updateSections();

signals:
	void sectionsChanged();

  public:
	SectionsModel(QObject* parent, BinaryViewRef data);
	virtual ~SectionsModel();

	const std::vector<SectionRef>& GetSections() const { return m_sections; }

	virtual void OnSectionAdded(BinaryNinja::BinaryView* data, BinaryNinja::Section* section) override;
	virtual void OnSectionRemoved(BinaryNinja::BinaryView* data, BinaryNinja::Section* section) override;
	virtual void OnSectionUpdated(BinaryNinja::BinaryView* data, BinaryNinja::Section* section) override;
};


class SectionsWidget : public QWidget
{
	Q_OBJECT

	BinaryViewRef m_data;
	SectionsModel* m_model;
	QGridLayout* m_layout;
	bool m_isRebuilding;

	void rebuildLayout();

  public:
	SectionsWidget(QWidget* parent, BinaryViewRef data);
	virtual ~SectionsWidget();
	const std::vector<SectionRef>& GetSections() const { return m_model->GetSections(); }
};
