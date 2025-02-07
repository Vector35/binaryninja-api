#pragma once

#include "uitypes.h"
#include <QString>
#include <QObject>
#include <QVersionNumber>
#include <QDateTime>
#include "binaryninjaapi.h"

class BINARYNINJAUIAPI UpdateInfoFetcher : public QObject
{
	Q_OBJECT

public:
	struct Version
	{
		QString versionStringToGiveToMainWindow;
		QVersionNumber version;
		QDateTime date;
		bool isCurrent = false;
		Version(BNUpdateVersionNew);
	};
	struct ChangelogEntryItem
	{
		QString author;
		QString commit;
		QString body;
		bool isHidden = false;
		ChangelogEntryItem(const QString& author = "", const QString& commit = "", const QString& body = "", const bool isHidden = false)
			: author(author), commit(commit), body(body), isHidden(isHidden) {};
		/// In-struct cache for wrapped text
		mutable QString bodyWrapCache;
	};
	struct ChangelogEntry
	{
		QVersionNumber version;
		QDateTime date;
		bool isNew = false;
		std::vector<ChangelogEntryItem> entryItems;
		ChangelogEntry(BNChangelogEntry);
	};
	struct Channel
	{
		QString name;
		QString description;
		std::vector<Version> versions;
		std::vector<ChangelogEntry> changelog;
		Channel(BNUpdateChannelFullInfo);
		Channel() {};
	};
	enum FetchError
	{
		NoError,
		ConnectionError,
		DeserError
	};

private:
	std::vector<Channel> m_channels;
	std::mutex m_infoMutex;
	std::atomic<bool> m_done = false;

public:
	UpdateInfoFetcher() {};
	bool done() { return m_done; }
	void startFetch();
	const std::vector<Channel>& getChannels();
	const Channel* getActiveChannel();
	std::vector<ChangelogEntry> getFilteredChangelog();
signals:
	void fetchCompleted(const FetchError& error);
};