#pragma once

#include <QThread>
#include <QtWidgets/QWidget>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QComboBox>
#include "viewframe.h"
#include "binaryninjaapi.h"

struct BaseDetectionSettings
{
	std::string Architecture;
	std::string Analysis;
	int MinStrlen;
	int PageSize;
};

namespace BinaryNinja
{
	class BaseDetection
	{
		BinaryViewRef m_view;
		BaseDetectionSettings m_settings;
		bool m_wait;
		Ref<Logger> m_logger;

		// Points of interest
		std::set<uint64_t> m_stringOffsets;
		std::set<uint64_t> m_funcOffsets;
		std::set<uint64_t> m_dataVariableOffsets;

		// Identified pointer values
		std::set<uint64_t> m_pointers;

		static inline bool m_abort {false};
		static inline std::mutex m_mutex {};

		void runAnalysis();
		bool identifyPointers();
		void identifyPointsOfInterest();

	public:
		void AbortAnalysis() { m_abort = true; }
		static bool AnalysisProgress(size_t complete, size_t total)
		{
			return true;
		}

		BaseDetection(BinaryViewRef bv, BaseDetectionSettings& settings);
		void DetectBaseAddress();
	};
}

struct BaseDetectionQtInputs
{
	QComboBox* ArchitectureBox;
	QComboBox* AnalysisBox;
	QLineEdit* StrlenLineEdit;
	QLineEdit* PageSizeLineEdit;
};

class BaseDetectionThread : public QThread
{
	Q_OBJECT
	BinaryViewRef m_view;
	BaseDetectionQtInputs* m_inputs {};
	void run() override;

public:
	BaseDetectionThread(BaseDetectionQtInputs* widgetInputs, BinaryViewRef bv)
	{
		m_inputs = widgetInputs;
		m_view = bv;
	}

signals:
	void resultReady(const QString& result);
};

class BaseDetectionWidget : public QWidget
{
	static constexpr std::int32_t m_maxColumns {2};
	std::pair<std::int32_t, std::int32_t> m_fieldPosition {};  // row, column
	QGridLayout* m_layout {};
	QPushButton* m_detectBaseAddressButton = nullptr;
	BaseDetectionQtInputs m_inputs;
	BinaryViewRef m_view;
	void detectBaseAddress();
	void handleResults(const QString& result);

public:
	BaseDetectionWidget(QWidget* parent, BinaryViewRef bv);
};