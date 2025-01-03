#include "ObjC.h"

using namespace BinaryNinja;
using namespace DSCObjC;
using namespace SharedCacheCore;

DSCObjCReader::DSCObjCReader(SharedCache* cache, size_t addressSize) :
	m_reader(VMReader(cache->GetVMMap())), m_addressSize(addressSize)
{
}

void DSCObjCReader::Read(void* dest, size_t len)
{
	m_reader.Read(dest, len);
}

std::string DSCObjCReader::ReadCString()
{
	return m_reader.ReadCString(m_reader.GetOffset());
}

uint8_t DSCObjCReader::Read8()
{
	return m_reader.Read8();
}

uint16_t DSCObjCReader::Read16()
{
	return m_reader.Read16();
}

uint32_t DSCObjCReader::Read32()
{
	return m_reader.Read32();
}

uint64_t DSCObjCReader::Read64()
{
	return m_reader.Read64();
}

int8_t DSCObjCReader::ReadS8()
{
	return m_reader.ReadS8();
}

int16_t DSCObjCReader::ReadS16()
{
	return m_reader.ReadS16();
}

int32_t DSCObjCReader::ReadS32()
{
	return m_reader.ReadS32();
}

int64_t DSCObjCReader::ReadS64()
{
	return m_reader.ReadS64();
}

uint64_t DSCObjCReader::ReadPointer()
{
	return m_reader.ReadPointer();
}

uint64_t DSCObjCReader::GetOffset() const
{
	return m_reader.GetOffset();
}

void DSCObjCReader::Seek(uint64_t offset)
{
	m_reader.Seek(offset);
}

void DSCObjCReader::SeekRelative(int64_t offset)
{
	m_reader.SeekRelative(offset);
}

VMReader& DSCObjCReader::GetVMReader()
{
	return m_reader;
}

std::shared_ptr<ObjCReader> DSCObjCProcessor::GetReader()
{
	return std::make_shared<DSCObjCReader>(m_cache, m_data->GetAddressSize());
}

void DSCObjCProcessor::GetRelativeMethod(ObjCReader* reader, method_t& meth)
{
	if (m_customRelativeMethodSelectorBase.has_value())
	{
		meth.name = m_customRelativeMethodSelectorBase.value() + reader->ReadS32();
		meth.types = reader->GetOffset() + reader->ReadS32();
		meth.imp = reader->GetOffset() + reader->ReadS32();
	}
	else
	{
		ObjCProcessor::GetRelativeMethod(reader, meth);
	}
}

uint64_t DSCObjCProcessor::GetObjCRelativeMethodBaseAddress(ObjCReader* reader)
{
	auto objCRelativeMethodsBaseAddr = m_cache->GetObjCRelativeMethodBaseAddress(static_cast<DSCObjCReader*>(reader)->GetVMReader());
	m_customRelativeMethodSelectorBase = objCRelativeMethodsBaseAddr;
	return objCRelativeMethodsBaseAddr;
}

DSCObjCProcessor::DSCObjCProcessor(BinaryView* data, SharedCache* cache, bool isBackedByDatabase) :
	ObjCProcessor(data, "SharedCache.ObjC", isBackedByDatabase, true), m_cache(cache)
{
}
