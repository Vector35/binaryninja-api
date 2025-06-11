#pragma once

#include <string>
#include <cstdint>
#include <cstdio>
#include <optional>

// Call this when initializing the plugin so that the process file descriptor limit is raised.
uint64_t AdjustFileDescriptorLimit();

enum MapStatus : int
{
	Success,
	// TODO: Split this error out into more contextual errors.
	Error,
};

struct MappedFile
{
	uint8_t* _mmap = nullptr;
	size_t len = 0;

#ifdef _MSC_VER
	HANDLE hFile = INVALID_HANDLE_VALUE;
#else
	FILE* fd = nullptr;
#endif

	MappedFile() = default;

	~MappedFile();

	MappedFile(const MappedFile&) = delete;

	MappedFile& operator=(const MappedFile&) = delete;

	MappedFile(MappedFile&& other) noexcept : _mmap(other._mmap), len(other.len)
	{
#ifdef _MSC_VER
		hFile = other.hFile;
		// Don't close the hFile in the move.
		other.hFile = nullptr;
#else
		fd = other.fd;
		// Don't close the fd in the move.
		other.fd = nullptr;
#endif
		other._mmap = nullptr;
	}

	// I hate C++
	MappedFile& operator=(MappedFile&& other) noexcept
	{
		if (this != &other)
		{
			Unmap();
#ifdef _MSC_VER
			if (hFile != nullptr)
			{
				CloseHandle(hFile);
			}
			hFile = other.hFile;
			// Don't close the hFile in the move.
			other.hFile = nullptr;
#else
			if (fd != nullptr)
			{
				fclose(fd);
			}
			fd = other.fd;
			// Don't close the fd in the move.
			other.fd = nullptr;
#endif
			len = other.len;
			_mmap = other._mmap;
			other._mmap = nullptr;
		}
		return *this;
	}

	static std::optional<MappedFile> OpenFile(const std::string& path);

	MapStatus Map();

	MapStatus Unmap();
};
