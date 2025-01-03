#include "objc.h"

using namespace BinaryNinja;

MachoObjCReader::MachoObjCReader(BinaryView* data) : m_reader(BinaryReader(data))
{
}

void MachoObjCReader::Read(void* dest, size_t len)
{
	m_reader.Read(dest, len);
}

std::string MachoObjCReader::ReadCString()
{
	return m_reader.ReadCString();
}

uint8_t MachoObjCReader::Read8()
{
	return m_reader.Read8();
}

uint16_t MachoObjCReader::Read16()
{
	return m_reader.Read16();
}

uint32_t MachoObjCReader::Read32()
{
	return m_reader.Read32();
}

uint64_t MachoObjCReader::Read64()
{
	return m_reader.Read64();
}

int8_t MachoObjCReader::ReadS8()
{
	return static_cast<int8_t>(m_reader.Read8());
}

int16_t MachoObjCReader::ReadS16()
{
	return static_cast<int16_t>(m_reader.Read16());
}

int32_t MachoObjCReader::ReadS32()
{
	return static_cast<int32_t>(m_reader.Read32());
}

int64_t MachoObjCReader::ReadS64()
{
	return static_cast<int64_t>(m_reader.Read64());
}

uint64_t MachoObjCReader::ReadPointer()
{
	return m_reader.ReadPointer();
}

uint64_t MachoObjCReader::GetOffset() const
{
	return m_reader.GetOffset();
}

void MachoObjCReader::Seek(uint64_t offset)
{
	m_reader.Seek(offset);
}

void MachoObjCReader::SeekRelative(int64_t offset)
{
	m_reader.SeekRelative(offset);
}

std::shared_ptr<ObjCReader> MachoObjCProcessor::GetReader()
{
	return std::make_shared<MachoObjCReader>(m_data);
}

bool MachoObjCProcessor::ViewHasObjCMetadata(BinaryView* data)
{
	return (data->GetSectionByName("__objc_classlist") || data->GetSectionByName("__objc_catlist")
		|| data->GetSectionByName("__objc_protolist"));
}

MachoObjCProcessor::MachoObjCProcessor(BinaryView* data, bool isBackedByDatabase) :
	ObjCProcessor(data, "macho.objc", isBackedByDatabase)
{
}
