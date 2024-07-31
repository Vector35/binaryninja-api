#include "binaryninjaapi.h"

using namespace BinaryNinja;


bool MemoryMap::AddBinaryMemoryRegion(const std::string& name, uint64_t start, Ref<BinaryView> source, uint32_t flags)
{
	return BNAddBinaryMemoryRegion(m_object, name.c_str(), start, source->GetObject(), flags);
}

bool MemoryMap::AddDataMemoryRegion(const std::string& name, uint64_t start, const DataBuffer& source, uint32_t flags)
{
	return BNAddDataMemoryRegion(m_object, name.c_str(), start, source.GetBufferObject(), flags);
}

bool MemoryMap::AddRemoteMemoryRegion(const std::string& name, uint64_t start, FileAccessor* source, uint32_t flags)
{
	return BNAddRemoteMemoryRegion(m_object, name.c_str(), start, source->GetCallbacks(), flags);
}

bool MemoryMap::RemoveMemoryRegion(const std::string& name)
{
	return BNRemoveMemoryRegion(m_object, name.c_str());
}

std::string MemoryMap::GetActiveMemoryRegionAt(uint64_t addr)
{
	char* name = BNGetActiveMemoryRegionAt(m_object, addr);
	std::string result = name;
	BNFreeString(name);
	return result;
}

uint32_t MemoryMap::GetMemoryRegionFlags(const std::string& name)
{
	return BNGetMemoryRegionFlags(m_object, name.c_str());
}

bool MemoryMap::SetMemoryRegionFlags(const std::string& name, uint32_t flags)
{
	return BNSetMemoryRegionFlags(m_object, name.c_str(), flags);
}

bool MemoryMap::IsMemoryRegionEnabled(const std::string& name)
{
	return BNIsMemoryRegionEnabled(m_object, name.c_str());
}

bool MemoryMap::SetMemoryRegionEnabled(const std::string& name, bool enabled)
{
	return BNSetMemoryRegionEnabled(m_object, name.c_str(), enabled);
}

bool MemoryMap::IsMemoryRegionRebaseable(const std::string& name)
{
	return BNIsMemoryRegionRebaseable(m_object, name.c_str());
}

bool MemoryMap::SetMemoryRegionRebaseable(const std::string& name, bool rebaseable)
{
	return BNSetMemoryRegionRebaseable(m_object, name.c_str(), rebaseable);
}

uint8_t MemoryMap::GetMemoryRegionFill(const std::string& name)
{
	return BNGetMemoryRegionFill(m_object, name.c_str());
}

bool MemoryMap::SetMemoryRegionFill(const std::string& name, uint8_t fill)
{
	return BNSetMemoryRegionFill(m_object, name.c_str(), fill);
}

void MemoryMap::Reset()
{
	BNResetMemoryMap(m_object);
}
