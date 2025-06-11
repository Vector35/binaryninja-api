#include "MappedFileAccessor.h"

std::shared_ptr<MappedFileAccessor> MappedFileAccessor::Open(const std::string& filePath)
{
	auto file = MappedFile::OpenFile(filePath);
	if (!file.has_value())
		return nullptr;
	if (file->Map() != MapStatus::Success)
		return nullptr;
	return std::make_shared<MappedFileAccessor>(std::move(*file));
}

// TODO: Will obviously not work on 32bit binaries, need to make WritePointer64 and 32 equiv.
void MappedFileAccessor::WritePointer(size_t address, size_t pointer)
{
	if (address + sizeof(size_t*) > Length())
		throw UnmappedAccessException(address + sizeof(size_t*), Length());
	m_dirty = true;
	*reinterpret_cast<size_t*>(&m_file._mmap[address]) = pointer;
}

std::string MappedFileAccessor::ReadNullTermString(size_t address, const size_t maxLength) const
{
	if (address > Length())
		return "";
	// If we are not given a maxLength (i.e. -1) than we will set the max address to the length of the file.
	const size_t maxAddr = (maxLength != -1) ? std::min(address + maxLength, Length()) : Length();
	// Read a null-terminated string manually to avoid errors related to string length on Linux.
	std::string str;
	str.reserve(140);
	for (size_t currAddr = address; currAddr < maxAddr; ++currAddr)
	{
		char c = m_file._mmap[currAddr];
		if (c == '\0')
			break;
		str += c;
	}
	str.shrink_to_fit();
	return str;
}

uint8_t MappedFileAccessor::ReadUInt8(size_t address) const
{
	return Read<uint8_t>(address);
}

int8_t MappedFileAccessor::ReadInt8(size_t address) const
{
	return Read<int8_t>(address);
}

uint16_t MappedFileAccessor::ReadUInt16(size_t address) const
{
	return Read<uint16_t>(address);
}

int16_t MappedFileAccessor::ReadInt16(size_t address) const
{
	return Read<int16_t>(address);
}


uint32_t MappedFileAccessor::ReadUInt32(size_t address) const
{
	return Read<uint32_t>(address);
}

int32_t MappedFileAccessor::ReadInt32(size_t address) const
{
	return Read<int32_t>(address);
}

uint64_t MappedFileAccessor::ReadUInt64(size_t address) const
{
	return Read<uint64_t>(address);
}

int64_t MappedFileAccessor::ReadInt64(size_t address) const
{
	return Read<int64_t>(address);
}

BinaryNinja::DataBuffer MappedFileAccessor::ReadBuffer(size_t addr, size_t length) const
{
	if (addr + length > Length())
		throw UnmappedAccessException(addr + length, Length());
	return {&m_file._mmap[addr], length};
}

std::pair<const uint8_t*, const uint8_t*> MappedFileAccessor::ReadSpan(size_t addr, size_t length)
{
	if (addr + length > Length())
		throw UnmappedAccessException(addr + length, Length());
	const uint8_t* data = &m_file._mmap[addr];
	return {data, data + length};
}

void MappedFileAccessor::Read(void* dest, size_t addr, size_t length) const
{
	if (addr + length > Length())
		throw UnmappedAccessException(addr + length, Length());
	memcpy(dest, &m_file._mmap[addr], length);
}

template <typename T>
T MappedFileAccessor::Read(size_t address) const
{
	T result;
	Read(&result, address, sizeof(T));
	return result;
}
