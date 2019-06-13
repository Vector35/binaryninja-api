#pragma once

#include <QtCore/QString>
#include <map>
#include <set>
#include <string>
#include "binaryninjaapi.h"
#include "uicontext.h"

class ViewFrame;
class ViewType;

// This base class is required for building the Python bindings. The other base classes of FileContext are
// ignored (as they have no functions that should be exported to Python), but this would leave the binding
// generator with a derived class with no base and a compiler error.
class FileContextBase
{
public:
	FileContextBase() {}
};

class BINARYNINJAUIAPI FileContext: public FileContextBase, public BinaryNinja::NavigationHandler
{
	QString m_filename;
	bool m_isValidSaveFilename;
	FileMetadataRef m_file;

	BinaryViewRef m_rawData;
	std::map<QString, BinaryViewRef> m_dataViews;

	ViewFrame* m_currentViewFrame;
	std::set<QObject*> m_refs;

	static std::set<FileContext*> m_openFiles;

	void createBinaryViews();

public:
	FileContext(FileMetadataRef file, BinaryViewRef rawData, const QString& filename = QString(), bool isValidSaveName = false, bool createViews = true);
	virtual ~FileContext();

	void registerReference(QWidget* widget);

	void close();
	static void closeAllOpenFiles();

	BinaryViewRef getRawData() const { return m_rawData; }
	QString getFilename() const { return m_filename; }
	ViewFrame* getCurrentViewFrame() const { return m_currentViewFrame; }

	bool isValidSaveFilename() const { return m_isValidSaveFilename; }
	void markAsSaved(const QString& filename);

	bool isModified();

	BinaryViewRef createDataView(const QString& type);
	BinaryViewRef getDataView(const QString& type, bool createView = false);
	std::vector<BinaryViewRef> getAllDataViews();

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

	static FileContext* newFile();
	static FileContext* openFilename(const QString& path);
};
