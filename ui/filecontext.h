#pragma once

#include <QtCore/QString>
#include <map>
#include <set>
#include <string>
#include <ctime>
#include "binaryninjaapi.h"
#include "uicontext.h"

class View;
class ViewFrame;
class ViewType;
class SyncGroup;

// This base class is required for building the Python bindings. The other base classes of FileContext are
// ignored (as they have no functions that should be exported to Python), but this would leave the binding
// generator with a derived class with no base and a compiler error.
class FileContextBase
{
  public:
	FileContextBase() {}
};

class BINARYNINJAUIAPI FileContext : public FileContextBase, public BinaryNinja::NavigationHandler
{
	QString m_filename;
	bool m_isValidSaveFilename;
	FileMetadataRef m_file;

	BinaryViewRef m_rawData;
	std::map<QString, BinaryViewRef> m_dataViews;

	ViewFrame* m_currentViewFrame;
	std::map<QObject*, QMetaObject::Connection> m_refs;

	std::vector<SyncGroup*> m_syncGroups;
	std::map<ViewFrame*, std::pair<View*, ViewLocation>> m_syncLastLocation;
	bool m_suspendSync = false;

	static std::set<FileContext*> m_openFiles;

	void createBinaryViews();

  public:
	FileContext(FileMetadataRef file, BinaryViewRef rawData, const QString& filename = QString(),
	    bool isValidSaveName = false, bool createViews = true);
	virtual ~FileContext();

	void registerReference(QObject* widget);
	void unregisterReference(QObject* widget);

	void close();
	static void closeAllOpenFiles();

	BinaryViewRef getRawData() const { return m_rawData; }
	FileMetadataRef getMetadata() const { return m_file; }
	QString getFilename() const { return m_filename; }
	void setFilename(QString newName) { m_filename = newName; }
	ViewFrame* getCurrentViewFrame() const { return m_currentViewFrame; }
	QString getTabName(QWidget* widget);
	QString getShortFileName(QWidget* widget);

	bool isValidSaveFilename() const { return m_isValidSaveFilename; }
	void markAsSaved(const QString& filename);

	bool isModified();

	BinaryViewRef createDataView(const QString& type);
	BinaryViewRef getDataView(const QString& type, bool createView = false);
	std::vector<BinaryViewRef> getAllDataViews();
	void refreshDataViewCache();

	void setCurrentViewFrame(ViewFrame* view);

	virtual std::string GetCurrentView() override;
	virtual uint64_t GetCurrentOffset() override;
	virtual bool Navigate(const std::string& view, uint64_t offset) override;

	QString getBestType();
	std::vector<QString> getAvailableTypes();
	bool isTypeAvailable(const QString& type);
	bool resolveType(const QString& type, ViewType*& viewType, BinaryViewTypeRef& data);
	bool resolveTypeAndData(const QString& type, ViewType*& viewType, BinaryViewRef& data);

	void updateAnalysis();

	SyncGroup* newSyncGroup();
	SyncGroup* syncGroupById(int id);
	void deleteSyncGroup(SyncGroup* syncGroup);
	SyncGroup* syncGroupForFrame(ViewFrame* frame);
	void removeFrame(ViewFrame* frame);
	const std::vector<SyncGroup*>& allSyncGroups() const { return m_syncGroups; }

	void forceLocationSyncForFrame(ViewFrame* frame);
	bool syncLocation(ViewFrame* frame, View* view, const ViewLocation& location);
	void suspendSync() { m_suspendSync = true; }
	void resumeSync() { m_suspendSync = false; }

	static FileContext* newFile();
	static FileContext* openFilename(const QString& path);
	static const std::set<FileContext*>& getOpenFileContexts();
};
