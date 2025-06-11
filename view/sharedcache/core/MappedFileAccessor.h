#pragma once

#include "binaryninjaapi.h"
#include "MappedFile.h"

#include <cstdint>
#include <list>

class UnmappedAccessException : public std::exception
{
	uint64_t m_address;
	uint64_t m_fileLen;

public:
	explicit UnmappedAccessException(uint64_t address, uint64_t fileLength) : m_address(address), m_fileLen(fileLength)
	{}

	virtual const char* what() const throw()
	{
		thread_local std::string message;
		message =
			fmt::format("Tried to access unmapped address {0:x} for file with length of {1:x}", m_address, m_fileLen);
		return message.c_str();
	}
};

// std::enable_shared_from_this allows weak pointers to "revive" the shared pointer in the FileAccessorCache.
class MappedFileAccessor : public std::enable_shared_from_this<MappedFileAccessor>
{
	MappedFile m_file;
	bool m_dirty = false;

public:
	explicit MappedFileAccessor(MappedFile file) : m_file(std::move(file)) {}

	~MappedFileAccessor() = default;

	MappedFileAccessor(const MappedFileAccessor&) = delete;

	MappedFileAccessor& operator=(const MappedFileAccessor&) = delete;

	MappedFileAccessor(MappedFileAccessor&&) noexcept = default;

	MappedFileAccessor& operator=(MappedFileAccessor&&) noexcept = default;

	static std::shared_ptr<MappedFileAccessor> Open(const std::string& filePath);

	size_t Length() const { return m_file.len; };

	void* Data() const { return m_file._mmap; };

	bool IsDirty() const { return m_dirty; }

	/**
	 * Writes to files are implemented for performance reasons and should be treated with utmost care
	 *
	 * They _MAY_ disappear as _soon_ as you release the lock on the file.
	 * They may also NOT disappear for the lifetime of the application.
	 *
	 * The former is more likely to occur when concurrent DSC processing is happening. The latter is the typical
	 * scenario.
	 *
	 * This is used explicitly for slide information in a locked scope and _NOTHING_ else. It should probably not be
	 * used for anything else.
	 *
	 * \param address The address to write the pointer to
	 * \param pointer The pointer to be written
	 */
	void WritePointer(size_t address, size_t pointer);

	std::string ReadNullTermString(size_t address, size_t maxLength = -1) const;

	uint8_t ReadUInt8(size_t address) const;

	int8_t ReadInt8(size_t address) const;

	uint16_t ReadUInt16(size_t address) const;

	int16_t ReadInt16(size_t address) const;

	uint32_t ReadUInt32(size_t address) const;

	int32_t ReadInt32(size_t address) const;

	uint64_t ReadUInt64(size_t address) const;

	int64_t ReadInt64(size_t address) const;

	BinaryNinja::DataBuffer ReadBuffer(size_t addr, size_t length) const;

	// Returns a range of pointers within the mapped memory region corresponding to
	// {addr, length}.
	// WARNING: The pointers returned by this method is only valid for the lifetime
	// of this file accessor.
	// TODO: This should use std::span<const uint8_t> once the minimum supported
	// C++ version supports it.
	std::pair<const uint8_t*, const uint8_t*> ReadSpan(size_t addr, size_t length);

	void Read(void* dest, size_t addr, size_t length) const;

	template <typename T>
	T Read(size_t address) const;
};
