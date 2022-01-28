#pragma once

#include <QtCore/QFile>
#include "binaryninjaapi.h"
#include "action.h"

class BINARYNINJAUIAPI QFileAccessor : public BinaryNinja::FileAccessor
{
	QFile* m_file;
	QString m_error;

public:
	QFileAccessor(const QString& name, bool write = false);
	virtual ~QFileAccessor();

	virtual bool IsValid() const;
	virtual QString GetError() const;
	virtual uint64_t GetLength() const;

	virtual size_t Read(void* dest, uint64_t offset, size_t len);
	virtual size_t Write(uint64_t offset, const void* src, size_t len);

	void Close();
};
