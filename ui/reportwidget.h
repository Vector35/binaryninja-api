#pragma once

#include <QtWidgets/QWidget>
#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QScrollArea>
#include <QtWebEngineWidgets/QWebEngineView>
#include <QtWebEngineWidgets/QWebEngineScript>
#include <QtWebEngineWidgets/QWebEngineScriptCollection>
#include <QtWebEngineWidgets/QWebEnginePage>
#include <QtWebEngineWidgets/QWebEngineSettings>
#include "binaryninjaapi.h"
#include "action.h"
#include "theme.h"

class WebPage2 : public QWebEnginePage
{
	Q_OBJECT

public:
	WebPage2(QObject *parent = nullptr) : QWebEnginePage(parent) {}

protected:
	virtual bool acceptNavigationRequest(const QUrl &url, QWebEnginePage::NavigationType type, bool isMainFrame);

Q_SIGNALS:
	void linkClicked(const QUrl&);
};

class BINARYNINJAUIAPI ReportWidget: public QScrollArea, public UIActionHandler
{
	Q_OBJECT

	QWebEngineView* m_contents;
	BinaryViewRef m_view;
	std::string m_original;
	std::string m_title;
	BNReportType m_type;
	std::string m_plaintext;

private Q_SLOTS:
	void onLinkClicked(QUrl url);

public:
	ReportWidget(QWidget* parent, BinaryViewRef view, const std::string& contents,
		BNReportType type, const std::string& title, const std::string& plaintext = "");
	std::string getContents() const { return m_original; }
	std::string getTitle() const { return m_title; }
	BNReportType getType() const { return m_type; }
	std::string getPlainText() const { return m_plaintext; }

	void save();
	void saveAs();
};
