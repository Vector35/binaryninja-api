#pragma once

#include <QtWidgets/QWidget>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QComboBox>
#include "viewframe.h"
#include "binaryninjaapi.h"

namespace BinaryNinja
{
	class BaseDetection {
		BinaryViewRef m_view;
		Ref<Logger> m_logger;	

		public:
			BaseDetection(BinaryViewRef bv, std::string arch, std::string analysis, uint32_t minStr, uint32_t pageSize);
	};
}

class BaseDetectionWidgetInputs {
	public:
		QComboBox* ArchitectureBox;
		QComboBox* AnalysisBox;
		QLineEdit* StrlenLineEdit;
		QLineEdit* PageSizeLineEdit;
};

class BaseDetectionWidget : public QWidget
{
	static constexpr std::int32_t m_maxColumns {2};
	std::pair<std::int32_t, std::int32_t> m_fieldPosition {};  // row, column
	QGridLayout* m_layout {};
	QPushButton* m_detectBaseAddressButton = nullptr;

	BaseDetectionWidgetInputs* m_inputs {};
	BinaryViewRef m_view;

	void detectBaseAddress();

	public:
		BaseDetectionWidget(QWidget* parent, BinaryViewRef bv);
};