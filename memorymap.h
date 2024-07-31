#pragma once

#include "binaryninjacore.h"
#include "refcount.h"
#include <string>

namespace BinaryNinja
{

	class BinaryView;
	class DataBuffer;
	class FileAccessor;

	class MemoryMap
	{
		BNBinaryView* m_object;

	public:
		MemoryMap(BNBinaryView* view): m_object(view) {}
		~MemoryMap() = default;

		bool AddBinaryMemoryRegion(const std::string& name, uint64_t start, Ref<BinaryView> source, uint32_t flags = 0);
		bool AddDataMemoryRegion(const std::string& name, uint64_t start, const DataBuffer& source, uint32_t flags = 0);
		bool AddRemoteMemoryRegion(const std::string& name, uint64_t start, FileAccessor* source, uint32_t flags = 0);
		bool RemoveMemoryRegion(const std::string& name);
		std::string GetActiveMemoryRegionAt(uint64_t addr);
		uint32_t GetMemoryRegionFlags(const std::string& name);
		bool SetMemoryRegionFlags(const std::string& name, uint32_t flags);
		bool IsMemoryRegionEnabled(const std::string& name);
		bool SetMemoryRegionEnabled(const std::string& name, bool enabled);
		bool IsMemoryRegionRebaseable(const std::string& name);
		bool SetMemoryRegionRebaseable(const std::string& name, bool rebaseable);
		uint8_t GetMemoryRegionFill(const std::string& name);
		bool SetMemoryRegionFill(const std::string& name, uint8_t fill);
		void Reset();
	};

}
