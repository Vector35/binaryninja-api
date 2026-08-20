#pragma once

#include <QThread>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QRadioButton>
#include <QtWidgets/QTableWidget>
#include <QHeaderView>
#include <QCoreApplication>
#include "theme.h"
#include "fontsettings.h"
#include "expandablegroup.h"
#include "viewframe.h"
#include "binaryninjaapi.h"
#include "binaryninjacore.h"
#include "progresstask.h"

struct BaseAddressDetectionQtInputs
{
	QComboBox* ArchitectureBox;
	QRadioButton* SamplingModeRadio;
	QRadioButton* InstructionAnalysisModeRadio;
	QLabel* AnalysisLabel;
	QComboBox* AnalysisBox;
	QLabel* StrlenLabel;
	QLineEdit* StrlenLineEdit;
	QLabel* AlignmentLabel;
	QLineEdit* AlignmentLineEdit;
	QLabel* LowerBoundaryLabel;
	QLineEdit* LowerBoundary;
	QLabel* UpperBoundaryLabel;
	QLineEdit* UpperBoundary;
	QLabel* POILabel;
	QComboBox* POIBox;
	QLabel* MaxPointersPerClusterLabel;
	QLineEdit* MaxPointersPerCluster;
};

struct BaseAddressDetectionQtResults
{
	std::string Status;
	std::set<std::pair<size_t, uint64_t>> Scores;
	BNBaseAddressDetectionConfidence Confidence;
	BNBaseAddressDetectionAnalysisMode AnalysisMode = SamplingBaseAddressDetection;
	std::map<uint64_t, std::vector<BNBaseAddressDetectionReason>> Reasons;
	uint64_t LastTestedBaseAddress;
};

class BaseAddressDetectionThread : public QThread
{
	Q_OBJECT
	BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;
	BinaryNinja::BaseAddressDetection* m_baseDetection = nullptr;
	BaseAddressDetectionQtInputs* m_inputs {};
	void run() override;

public:
	BaseAddressDetectionThread(BaseAddressDetectionQtInputs* widgetInputs,
		BinaryNinja::Ref<BinaryNinja::BinaryView> bv);
	~BaseAddressDetectionThread();
	void Abort() { m_baseDetection->Abort(); }
	bool IsAborted() { return m_baseDetection->IsAborted(); }

signals:
	void ResultReady(const BaseAddressDetectionQtResults& result);
};

class BaseAddressDetectionWidget : public QWidget
{
	BaseAddressDetectionThread* m_worker;
	BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;
	BaseAddressDetectionQtInputs m_inputs;

	QGridLayout* m_layout {};
	QPushButton* m_startButton = nullptr;
	QPushButton* m_abortButton = nullptr;
	QLabel* m_preferredBaseLabel;
	QLabel* m_preferredBase;
	QLabel* m_confidenceLabel;
	QLabel* m_confidence;
	QLabel* m_status;
	QLineEdit* m_reloadBase;
	QPushButton* m_rebaseButton;
	QWidget* m_detectionModeWidget = nullptr;
	QTableWidget* m_resultsTableWidget;
	ExpandableGroup* m_advancedSettingsGroup = nullptr;

	void DetectBaseAddress();
	const std::string GetRebaseViewName();
	void RebaseWithFullAnalysis();
	void Abort();
	void HandleResults(const BaseAddressDetectionQtResults& results);
	void HideResultsWidgets(bool hide);
	void CreateAdvancedSettingsGroup();
	void ConfigureResultsTable(BNBaseAddressDetectionAnalysisMode analysisMode);
	void UpdateModeSpecificSettingsVisibility();
	void GetClickedBaseAddress(const QModelIndex& index);

public:
	BaseAddressDetectionWidget(QWidget* parent, BinaryNinja::Ref<BinaryNinja::BinaryView> bv);
};
