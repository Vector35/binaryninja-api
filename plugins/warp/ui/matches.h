#pragma once

#include <QSplitter>
#include <QProgressBar>

#include "filter.h"
#include "render.h"
#include "shared/fetcher.h"
#include "shared/function.h"

class WarpCurrentFunctionWidget : public QWidget
{
	Q_OBJECT
	FunctionRef m_current;

	QSplitter* m_splitter;
	QProgressBar* m_spinner;

	WarpFunctionTableWidget* m_tableWidget;
	WarpFunctionInfoWidget* m_infoWidget;

	LoggerRef m_logger;

	std::shared_ptr<WarpFetcher> m_fetcher;

public:
	explicit WarpCurrentFunctionWidget(QWidget* parent = nullptr);

	~WarpCurrentFunctionWidget() override = default;

	void SetFetcher(std::shared_ptr<WarpFetcher> fetcher);

	void SetCurrentFunction(FunctionRef current);

	FunctionRef GetCurrentFunction() { return m_current; };

	void UpdateMatches();
};
