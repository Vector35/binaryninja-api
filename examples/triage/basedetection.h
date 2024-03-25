#pragma once

#include <QThread>
#include <QtWidgets/QWidget>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QComboBox>
#include <limits>
#include <cmath>
#include "viewframe.h"
#include "binaryninjaapi.h"

// This is the minimum amount of pointers within a cluster that is required to be considered a searchable range
// TODO: we might want to make this a user setting
#define MIN_POINTER_THRESHOLD 2

// Mechanism to preserve memory, if we get to 1000 candidates, scrub all but 10
#define SCRUB_LOSING_CANDIDATES_THRESHOLD 1000
#define MAX_CANDIDATE_BASE_ADDRESSES 10

struct BaseDetectionSettings
{
	std::string Architecture;
	std::string Analysis;
	int MinStrlen;
	int PageSize;
};

struct BaseDetectionResults
{
	std::set<std::pair<size_t, uint64_t>> CandidateBaseAddresses;
};

namespace BinaryNinja
{
	class BaseDetection
	{
		BinaryViewRef m_view;
		BinaryReader *m_reader;
		BaseDetectionSettings m_settings;
		Ref<Logger> m_logger;
		Ref<Architecture> m_arch;

		// Points of interest
		std::set<uint64_t> m_stringOffsets;
		std::set<uint64_t> m_funcOffsets;
		std::set<uint64_t> m_dataVariableOffsets;

		// Identified pointer values
		std::set<uint64_t> m_pointers;

		// Top 10 base addressess with the most hits on POIs (after analysis)
		std::set<std::pair<size_t, uint64_t>> m_candidateBaseAddresses;


		static inline bool m_abort {false};

		bool tryReadPointerAt(uint64_t offset, uint64_t& value);
		bool identifyPointsOfInterest();
		bool identifyPointers();
		std::vector<std::set<uint64_t>> groupClusteredPointers();
		std::vector<std::set<uint64_t>> identifyRangesFromClusteredPointers(
			std::vector<std::set<uint64_t>>& clusters);
		void scrubLosingCandidates();
		void bruteForceSearch(std::vector<std::set<uint64_t>>& clusteredPointers,
			std::vector<std::set<uint64_t>>& ranges);

	public:
		static void AbortAnalysis() { m_abort = true; }
		BaseDetection(BinaryViewRef bv, BaseDetectionSettings& settings);
		bool Init();
		void DetectBaseAddress();
		void GetResults(BaseDetectionResults& results);
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
	void resultReady(const BaseDetectionResults& result);
};

class BaseDetectionWidget : public QWidget
{
	BinaryViewRef m_view;
	static constexpr std::int32_t m_maxColumns {2};
	std::pair<std::int32_t, std::int32_t> m_fieldPosition {};  // row, column
	QGridLayout* m_layout {};

	QPushButton* m_detectBaseAddressButton = nullptr;
	QPushButton* m_abortButton = nullptr;

	BaseDetectionQtInputs m_inputs;
	QLineEdit* m_result;

	void detectBaseAddress();
	void abortAnalysis();
	void handleResults(const BaseDetectionResults& results);

public:
	BaseDetectionWidget(QWidget* parent, BinaryViewRef bv);
};