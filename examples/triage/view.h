#pragma once

#include <QtWidgets/QScrollArea>
#include <QtWidgets/QPushButton>
#include "viewframe.h"
#include "byte.h"


class TriageView: public QScrollArea, public View
{
	BinaryViewRef m_data;
	uint64_t m_currentOffset = 0;
	ByteView* m_byteView = nullptr;
	QPushButton* m_fullAnalysisButton = nullptr;

public:
	TriageView(QWidget* parent, BinaryViewRef data);

	virtual BinaryViewRef getData() override;
	virtual uint64_t getCurrentOffset() override;
	virtual BNAddressRange getSelectionOffsets() override;
	virtual QFont getFont() override;
	virtual bool navigate(uint64_t addr) override;

	void setCurrentOffset(uint64_t offset);
	void navigateToFileOffset(uint64_t offset);

protected:
	virtual void focusInEvent(QFocusEvent* event) override;

private Q_SLOTS:
	void startFullAnalysis();
};


class TriageViewType: public ViewType
{
public:
	TriageViewType();
	virtual int getPriority(BinaryViewRef data, const QString& filename) override;
	virtual QWidget* create(BinaryViewRef data, ViewFrame* frame) override;
};
