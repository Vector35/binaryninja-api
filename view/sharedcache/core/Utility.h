#pragma once

#include <cstdint>
#include <map>

#include "binaryninjaapi.h"

#ifdef _MSC_VER
inline int CountTrailingZeros(uint64_t value)
{
	unsigned long index;  // 32-bit long on Windows
	if (_BitScanForward64(&index, value))
	{
		return index;
	}
	else
	{
		return 64;  // If the value is 0, return 64.
	}
}
#else
inline int CountTrailingZeros(uint64_t value)
{
	return value == 0 ? 64 : __builtin_ctzll(value);
}
#endif

BNSegmentFlag SegmentFlagsFromMachOProtections(int initProt, int maxProt);

int64_t readSLEB128(const uint8_t*& current, const uint8_t* end);

uint64_t readLEB128(const uint8_t*& current, const uint8_t* end);

uint64_t readValidULEB128(const uint8_t*& current, const uint8_t* end);

void ApplySymbol(BinaryNinja::Ref<BinaryNinja::BinaryView> view, BinaryNinja::Ref<BinaryNinja::TypeLibrary> typeLib,
	BinaryNinja::Ref<BinaryNinja::Symbol> symbol, BinaryNinja::Ref<BinaryNinja::Type> type = nullptr);

// Returns the "image name" for a given path.
// /blah/foo/bar/libObjCThing.dylib -> libObjCThing.dylib
std::string BaseFileName(const std::string& path);

bool IsSameFolderForFile(BinaryNinja::Ref<BinaryNinja::ProjectFile> a, BinaryNinja::Ref<BinaryNinja::ProjectFile> b);
bool IsSameFolder(BinaryNinja::Ref<BinaryNinja::ProjectFolder> a, BinaryNinja::Ref<BinaryNinja::ProjectFolder> b);

// Represents a range of addresses [start, end).
// Note that `end` is not included within the range.
struct AddressRange
{
	uint64_t start;
	uint64_t end;

	AddressRange(uint64_t start, uint64_t end) : start(start), end(end) {}

	AddressRange() : start(0), end(0) {}

	bool Overlaps(const AddressRange& b) const { return start < b.end && b.start < end; }

	bool operator<(const AddressRange& b) const { return start < b.start || (start == b.start && end < b.end); }

	friend bool operator<(const AddressRange& range, uint64_t address) { return range.end <= address; }

	friend bool operator<(uint64_t address, const AddressRange& range) { return address < range.start; }
};

// A map keyed by address ranges that can be looked up via any
// address within a range thanks to C++14's transparent comparators.
template <typename Value>
using AddressRangeMap = std::map<AddressRange, Value, std::less<>>;

// TODO: Document this!
template <typename T>
class WeakAllocPtr
{
protected:
	std::weak_ptr<T> m_weakPtr;                       // Weak reference to the object
	std::function<std::shared_ptr<T>()> m_allocator;  // Function to recreate the object

public:
	explicit WeakAllocPtr(std::function<std::shared_ptr<T>()> allocator) : m_allocator(allocator) {}

	WeakAllocPtr(std::weak_ptr<T> weakPtr, std::function<std::shared_ptr<T>()> allocator) : m_allocator(allocator)
	{
		if (weakPtr == nullptr)
		{
			m_weakPtr = {};
		}
		else
		{
			m_weakPtr = weakPtr;
		}
	}

	std::shared_ptr<T> lock()
	{
		std::shared_ptr<T> sharedPtr = m_weakPtr.lock();
		if (!sharedPtr)
		{
			sharedPtr = m_allocator();
			m_weakPtr = sharedPtr;
		}
		return sharedPtr;
	}

	std::shared_ptr<T> lock_no_allocate() { return m_weakPtr.lock(); }
};
