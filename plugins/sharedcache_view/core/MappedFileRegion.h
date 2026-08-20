#pragma once

#include "binaryninjaapi.h"

#include <memory>
#include <mutex>
#include <span>
#include <stdint.h>
#include <string>

class UnmappedAccessException : public std::runtime_error
{
public:
	UnmappedAccessException(uint64_t offset, uint64_t fileLength)
		: std::runtime_error(fmt::format("Tried to access offset {:#x} in file of length {:#x}", offset, fileLength))
	{}
};

// A memory-mapped region of a file. Owns the mmap for its entire lifetime.
// Data is mapped using MAP_PRIVATE, so modifications to the data are not persisted to disk.
class MappedFileRegion
{
	uint8_t* m_data = nullptr;
	size_t m_length = 0;
	std::string m_path;
	std::once_flag m_slidOnce;

	MappedFileRegion(const MappedFileRegion&) = delete;
	MappedFileRegion& operator=(const MappedFileRegion&) = delete;
	MappedFileRegion(MappedFileRegion&&) = delete;
	MappedFileRegion& operator=(MappedFileRegion&&) = delete;

	struct PrivateTag {};

public:
	MappedFileRegion(PrivateTag, uint8_t* data, size_t length, std::string path);
	~MappedFileRegion();

	// Opens file, mmaps with MAP_PRIVATE, closes fd immediately.
	// Returns nullptr on failure.
	static std::shared_ptr<MappedFileRegion> Open(const std::string& path);

	const std::string& Path() const { return m_path; }
	size_t Length() const { return m_length; }

	// Run `fn` exactly once. All callers block until the work is complete.
	template <typename F>
	void SlideOnce(F&& fn) { std::call_once(m_slidOnce, std::forward<F>(fn)); }

	// Typed reads -- bounds-checked with overflow-safe checks:
	//   if (sizeof(T) > m_length || offset > m_length - sizeof(T))
	uint8_t ReadUInt8(size_t offset) const;
	int8_t ReadInt8(size_t offset) const;
	uint16_t ReadUInt16(size_t offset) const;
	int16_t ReadInt16(size_t offset) const;
	uint32_t ReadUInt32(size_t offset) const;
	int32_t ReadInt32(size_t offset) const;
	uint64_t ReadUInt64(size_t offset) const;
	int64_t ReadInt64(size_t offset) const;

	std::string ReadNullTermString(size_t offset, size_t maxLen = -1) const;
	void Read(void* dest, size_t offset, size_t length) const;
	BinaryNinja::DataBuffer ReadBuffer(size_t offset, size_t length) const;
	std::span<const uint8_t> ReadSpan(size_t offset, size_t length) const;

	// Write. This is not persisted to disk. Used for applying slides only.
	void WriteUInt64(size_t offset, uint64_t value);

private:
	template <typename T>
	T Read(size_t offset) const;
};
