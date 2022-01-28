#pragma once

#include <QtWidgets/QWidget>
#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QScrollArea>
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
	#include <QtWebEngineWidgets/QWebEngineView>
	#include <QtWebEngineWidgets/QWebEngineScript>
	#include <QtWebEngineWidgets/QWebEngineScriptCollection>
	#include <QtWebEngineWidgets/QWebEnginePage>
	#include <QtWebEngineWidgets/QWebEngineSettings>
#else
	#include <QtWidgets/QTextBrowser>
#endif
#include "binaryninjaapi.h"
#include "action.h"
#include "theme.h"

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
class WebPage2 : public QWebEnginePage
{
	Q_OBJECT

  public:
	WebPage2(QObject* parent = nullptr) : QWebEnginePage(parent) {}

  protected:
	virtual bool acceptNavigationRequest(const QUrl& url, QWebEnginePage::NavigationType type, bool isMainFrame);

  Q_SIGNALS:
	void linkClicked(const QUrl&);
};
#endif

class BINARYNINJAUIAPI ReportWidget : public QScrollArea, public UIActionHandler
{
	Q_OBJECT

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
	QWebEngineView* m_contents;
#else
	QTextBrowser* m_contents;
#endif
	BinaryViewRef m_view;
	std::string m_original;
	std::string m_title;
	BNReportType m_type;
	std::string m_plaintext;

  private Q_SLOTS:
	void onLinkClicked(QUrl url);

  public:
	ReportWidget(QWidget* parent, BinaryViewRef view, const std::string& contents, BNReportType type,
	    const std::string& title, const std::string& plaintext = "");
	std::string getContents() const { return m_original; }
	std::string getTitle() const { return m_title; }
	BNReportType getType() const { return m_type; }
	std::string getPlainText() const { return m_plaintext; }

	void save();
	void saveAs();

	ReportWidget* duplicate();
};
