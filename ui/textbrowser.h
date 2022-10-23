#pragma once

#include <QtWidgets/QTextBrowser>
#include <QtGui/QTextDocument>
#include <QtGui/QTextBlock>
#include <QtGui/QTextFragment>
#include <QtGui/QImage>
#include <QtCore/QThread>
#include <QtCore/QMutex>
#include <QtCore/QWaitCondition>
#include <QtCore/QSharedPointer>
#include <queue>
#include <optional>
#include "binaryninjaapi.h"
#include "uitypes.h"

class TextBrowser;
class TextBrowserDownloadThread;

/*!

	\defgroup textbrowser TextBrowser
 	\ingroup uiapi
*/

/*!

    \ingroup textbrowser
*/
class BINARYNINJAUIAPI TextBrowserDownloadCache
{
	QMutex m_mutex;
	std::map<QUrl, QByteArray> m_downloadCache;
	std::set<QUrl> m_inProgress;

  public:
	TextBrowserDownloadCache();

	bool lookup(const QUrl& url, QByteArray& result);
	void add(const QUrl& url, const QByteArray& data);

	void beginRequest(const QUrl& url);
	void endRequest(const QUrl& url);
	bool isInProgress(const QUrl& url);
};

/*!

    \ingroup textbrowser
*/
class TextBrowserDownloadQueue : public QObject
{
	Q_OBJECT

	QMutex m_mutex;
	QWaitCondition m_cond;
	TextBrowser* m_owner;

	std::queue<QUrl> m_queue;

	size_t m_activeThreads = 0;

	static uint64_t AppendDataCallback(uint8_t* data, uint64_t len, void* ctxt);

  public:
	TextBrowserDownloadQueue(TextBrowser* owner);

	void stop();
	void threadFinished();
	bool processNextEvent(BinaryNinja::DownloadInstance* downloadInstance);
	void downloadData(const QUrl& name);

  Q_SIGNALS:
	void dataDownloaded(QUrl name, QByteArray contents);
};

/*!

    \ingroup textbrowser
*/
class TextBrowserDownloadThread : public QThread
{
	Q_OBJECT

	QMutex m_mutex;
	TextBrowserDownloadQueue* m_queue;

	BinaryNinja::Ref<BinaryNinja::DownloadProvider> m_provider;
	BinaryNinja::Ref<BinaryNinja::DownloadInstance> m_downloadInstance;

  protected:
	virtual void run() override;

  public:
	TextBrowserDownloadThread(TextBrowserDownloadQueue* queue);
};

/*!

    \ingroup textbrowser
*/
class BINARYNINJAUIAPI TextBrowser : public QTextBrowser
{
	Q_OBJECT

	QSharedPointer<TextBrowserDownloadCache> m_cache;
	bool m_ownedCache;

	TextBrowserDownloadQueue* m_queue;
	bool m_resizeImagesToWidth = false;

	std::set<QUrl> m_requested;
	std::optional<QUrl> m_markdownUrl;
	QString m_markdownPrefix;

	void resizeImageFragment(
	    QTextBlock& block, QTextFragment fragment, QTextImageFormat imgFormat, const QImage& contents);

  protected:
	virtual void resizeEvent(QResizeEvent* e) override;

  public:
	TextBrowser(QSharedPointer<TextBrowserDownloadCache> cache = QSharedPointer<TextBrowserDownloadCache>());
	virtual ~TextBrowser();

	void reset();
	virtual QVariant loadResource(int type, const QUrl& name) override;

	void resizeImagesToWidth();
	QSharedPointer<TextBrowserDownloadCache> cache() { return m_cache; }

	void downloadMarkdown(QUrl url, QString prefix = QString());

  private Q_SLOTS:
	void dataDownloaded(QUrl name, QByteArray contents);
};
