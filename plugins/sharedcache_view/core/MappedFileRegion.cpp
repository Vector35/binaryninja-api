#include "MappedFileRegion.h"

#ifdef _MSC_VER
#include <windows.h>
#else
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#endif


MappedFileRegion::MappedFileRegion(PrivateTag, uint8_t* data, size_t length, std::string path)
	: m_data(data), m_length(length), m_path(std::move(path))
{}

#ifndef _MSC_VER

std::shared_ptr<MappedFileRegion> MappedFileRegion::Open(const std::string& path)
{
	std::unique_ptr<FILE, decltype(&fclose)> fd(fopen(path.c_str(), "r"), fclose);
	if (!fd)
		return nullptr;

	fseek(fd.get(), 0L, SEEK_END);
	long fileLen = ftell(fd.get());
	if (fileLen <= 0)
	{
		if (fileLen < 0)
			BinaryNinja::LogErrorF("ftell failed for '{}': {}", path, strerror(errno));
		else
			BinaryNinja::LogErrorF("Cannot mmap empty file '{}'", path);
		return nullptr;
	}
	auto length = static_cast<size_t>(fileLen);
	void* result = mmap(nullptr, length, PROT_READ | PROT_WRITE, MAP_PRIVATE, fileno(fd.get()), 0);

	if (result == MAP_FAILED)
	{
		BinaryNinja::LogErrorF("mmap failed for '{}': {}", path, strerror(errno));
		return nullptr;
	}

	return std::make_shared<MappedFileRegion>(PrivateTag{}, static_cast<uint8_t*>(result), length, path);
}

MappedFileRegion::~MappedFileRegion()
{
	if (m_data)
	{
		munmap(m_data, m_length);
		m_data = nullptr;
	}
}

#else  // _MSC_VER

std::shared_ptr<MappedFileRegion> MappedFileRegion::Open(const std::string& path)
{
	HANDLE hFile = CreateFile(path.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return nullptr;

	LARGE_INTEGER fileSize;
	if (!GetFileSizeEx(hFile, &fileSize))
	{
		CloseHandle(hFile);
		return nullptr;
	}
	auto length = static_cast<size_t>(fileSize.QuadPart);

	HANDLE hMapping = CreateFileMapping(hFile,
		NULL,
		PAGE_WRITECOPY,
		0,
		0,
		NULL);

	if (hMapping == NULL)
	{
		BinaryNinja::LogErrorF("CreateFileMapping failed for '{}': error {}", path, GetLastError());
		CloseHandle(hFile);
		return nullptr;
	}

	auto* data = static_cast<uint8_t*>(MapViewOfFile(hMapping,
		FILE_MAP_COPY,
		0,
		0,
		0));

	// Save the error before CloseHandle potentially overwrites it.
	DWORD mapViewError = (data == nullptr) ? GetLastError() : 0;

	CloseHandle(hMapping);
	CloseHandle(hFile);

	if (!data)
	{
		BinaryNinja::LogErrorF("MapViewOfFile failed for '{}': error {}", path, mapViewError);
		return nullptr;
	}

	return std::make_shared<MappedFileRegion>(PrivateTag{}, data, length, path);
}

MappedFileRegion::~MappedFileRegion()
{
	if (m_data)
	{
		UnmapViewOfFile(m_data);
		m_data = nullptr;
	}
}

#endif  // _MSC_VER

void MappedFileRegion::WriteUInt64(size_t offset, uint64_t value)
{
	if (sizeof(uint64_t) > m_length || offset > m_length - sizeof(uint64_t))
		throw UnmappedAccessException(offset, m_length);
	memcpy(&m_data[offset], &value, sizeof(uint64_t));
}

uint8_t MappedFileRegion::ReadUInt8(size_t offset) const
{
	return Read<uint8_t>(offset);
}

int8_t MappedFileRegion::ReadInt8(size_t offset) const
{
	return Read<int8_t>(offset);
}

uint16_t MappedFileRegion::ReadUInt16(size_t offset) const
{
	return Read<uint16_t>(offset);
}

int16_t MappedFileRegion::ReadInt16(size_t offset) const
{
	return Read<int16_t>(offset);
}

uint32_t MappedFileRegion::ReadUInt32(size_t offset) const
{
	return Read<uint32_t>(offset);
}

int32_t MappedFileRegion::ReadInt32(size_t offset) const
{
	return Read<int32_t>(offset);
}

uint64_t MappedFileRegion::ReadUInt64(size_t offset) const
{
	return Read<uint64_t>(offset);
}

int64_t MappedFileRegion::ReadInt64(size_t offset) const
{
	return Read<int64_t>(offset);
}

std::string MappedFileRegion::ReadNullTermString(size_t offset, const size_t maxLen) const
{
	if (offset >= m_length)
		return "";

	const size_t remaining = m_length - offset;
	const size_t limit = (maxLen != static_cast<size_t>(-1)) ? std::min(maxLen, remaining) : remaining;
	const auto* begin = reinterpret_cast<const char*>(m_data + offset);
	const auto* end = begin + limit;
	const auto* nul = std::find(begin, end, '\0');
	return {begin, nul};
}

BinaryNinja::DataBuffer MappedFileRegion::ReadBuffer(size_t offset, size_t length) const
{
	if (length > m_length || offset > m_length - length)
		throw UnmappedAccessException(offset, m_length);
	return {&m_data[offset], length};
}

std::span<const uint8_t> MappedFileRegion::ReadSpan(size_t offset, size_t length) const
{
	if (length > m_length || offset > m_length - length)
		throw UnmappedAccessException(offset, m_length);
	return {&m_data[offset], length};
}

void MappedFileRegion::Read(void* dest, size_t offset, size_t length) const
{
	if (length > m_length || offset > m_length - length)
		throw UnmappedAccessException(offset, m_length);
	memcpy(dest, &m_data[offset], length);
}

template <typename T>
T MappedFileRegion::Read(size_t offset) const
{
	if (sizeof(T) > m_length || offset > m_length - sizeof(T))
		throw UnmappedAccessException(offset, m_length);
	T result;
	memcpy(&result, &m_data[offset], sizeof(T));
	return result;
}
