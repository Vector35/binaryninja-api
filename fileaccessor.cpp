#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


uint64_t FileAccessor::GetLengthCallback(void* ctxt)
{
	FileAccessor* file = (FileAccessor*)ctxt;
	return file->GetLength();
}


size_t FileAccessor::ReadCallback(void* ctxt, void* dest, uint64_t offset, size_t len)
{
	FileAccessor* file = (FileAccessor*)ctxt;
	return file->Read(dest, offset, len);
}


size_t FileAccessor::WriteCallback(void* ctxt, uint64_t offset, const void* src, size_t len)
{
	FileAccessor* file = (FileAccessor*)ctxt;
	return file->Write(offset, src, len);
}


FileAccessor::FileAccessor()
{
	m_callbacks.context = this;
	m_callbacks.getLength = GetLengthCallback;
	m_callbacks.read = ReadCallback;
	m_callbacks.write = WriteCallback;
}


FileAccessor::FileAccessor(BNFileAccessor* accessor): m_callbacks(*accessor)
{
}


CoreFileAccessor::CoreFileAccessor(BNFileAccessor* accessor): FileAccessor(accessor)
{
}


uint64_t CoreFileAccessor::GetLength() const
{
	return m_callbacks.getLength(m_callbacks.context);
}


size_t CoreFileAccessor::Read(void* dest, uint64_t offset, size_t len)
{
	return m_callbacks.read(m_callbacks.context, dest, offset, len);
}


size_t CoreFileAccessor::Write(uint64_t offset, const void* src, size_t len)
{
	return m_callbacks.write(m_callbacks.context, offset, src, len);
}

