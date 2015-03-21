#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


TemporaryFile::TemporaryFile()
{
	m_file = BNCreateTemporaryFile();
}


TemporaryFile::TemporaryFile(const DataBuffer& contents)
{
	m_file = BNCreateTemporaryFileWithContents(contents.GetBufferObject());
}


TemporaryFile::TemporaryFile(const string& contents)
{
	DataBuffer buf(contents.c_str(), contents.size());
	m_file = BNCreateTemporaryFileWithContents(buf.GetBufferObject());
}


TemporaryFile::TemporaryFile(BNTemporaryFile* file): m_file(file)
{
}


TemporaryFile::~TemporaryFile()
{
	if (m_file)
		BNFreeTemporaryFile(m_file);
}


string TemporaryFile::GetPath() const
{
	if (!m_file)
		return string();

	char* str = BNGetTemporaryFilePath(m_file);
	string result = str;
	BNFreeString(str);
	return result;
}


DataBuffer TemporaryFile::GetContents()
{
	if (!m_file)
		return DataBuffer();
	return DataBuffer(BNGetTemporaryFileContents(m_file));
}
