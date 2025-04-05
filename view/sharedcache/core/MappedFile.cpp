#ifdef _MSC_VER
	#include <windows.h>
#else
	#include <sys/mman.h>
	#include <fcntl.h>
	#include <cstdlib>
	#include <sys/resource.h>
#endif

#include "MappedFile.h"
#include "binaryninjaapi.h"

#ifndef _MSC_VER
uint64_t AdjustFileDescriptorLimit()
{
	// The soft file descriptor limit on Linux and Mac is a lot lower than
	// on Windows (1024 for Linux, 256 for Mac). Recent iOS shared caches
	// have 60+ files which may not leave much headroom if a user opens
	// more than one at a time. Attempt to increase the file descriptor
	// limit to 1024, and limit ourselves to caching half of them as a
	// memory vs performance trade-off (closing and re-opening a file
	// requires parsing and applying the slide information again).
	uint64_t maxFPLimit = 1024;

	// check for BN_SHAREDCACHE_FP_MAX
	//  if it exists, set maxFPLimit to that value
	if (auto env = getenv("BN_SHAREDCACHE_FP_MAX"); env)
	{
		// FIXME behav on 0 here is unintuitive, '0123' will interpret as octal and be 83 according to manpage. meh.
		maxFPLimit = strtoull(env, nullptr, 0);
		if (maxFPLimit < 10)
		{
			BinaryNinja::LogWarn(
				"BN_SHAREDCACHE_FP_MAX set to below 10. A value of at least 10 is recommended for performant analysis "
			    "on SharedCache Binaries.");
		}
		if (maxFPLimit == 0)
		{
			BinaryNinja::LogError("BN_SHAREDCACHE_FP_MAX set to 0. Adjusting to 1");
			maxFPLimit = 1;
		}
	}

	rlimit rlim {};
	getrlimit(RLIMIT_NOFILE, &rlim);
	uint64_t previousLimit = rlim.rlim_cur;
	uint64_t targetLimit = std::min(maxFPLimit, rlim.rlim_max);
	if (rlim.rlim_cur < targetLimit)
	{
		rlim.rlim_cur = targetLimit;
		if (setrlimit(RLIMIT_NOFILE, &rlim) < 0)
		{
			perror("setrlimit(RLIMIT_NOFILE)");
			rlim.rlim_cur = previousLimit;
		}
	}

	maxFPLimit = rlim.rlim_cur / 2;
	return maxFPLimit;
}

MappedFile::~MappedFile()
{
	Unmap();
	if (fd)
		fclose(fd);
}

std::optional<MappedFile> MappedFile::OpenFile(const std::string& path)
{
	MappedFile file;
	file._mmap = nullptr;
	file.fd = fopen(path.c_str(), "r");
	if (file.fd == nullptr)
		return std::nullopt;

	fseek(file.fd, 0L, SEEK_END);
	file.len = ftell(file.fd);
	fseek(file.fd, 0L, SEEK_SET);

	return file;
}

MapStatus MappedFile::Map()
{
	if (_mmap)
		return MapStatus::Success;

	void* result = mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fileno(fd), 0u);
	if (result == MAP_FAILED)
	{
		BinaryNinja::LogError("mmap failed: %s", strerror(errno));  // Use errno to log the reason
		return MapStatus::Error;
	}
	_mmap = static_cast<uint8_t*>(result);

	return MapStatus::Success;
}

MapStatus MappedFile::Unmap()
{
	if (_mmap)
	{
		munmap(_mmap, len);
		_mmap = nullptr;
	}
	return MapStatus::Success;
}
#else
uint64_t AdjustFileDescriptorLimit()
{
	return 0x1000000;
}

MappedFile::~MappedFile()
{
	Unmap();
	if (hFile)
		CloseHandle(hFile);
}

std::optional<MappedFile> MappedFile::OpenFile(const std::string& path)
{
	MappedFile file;
	file._mmap = nullptr;
	file.hFile = CreateFile(path.c_str(),  // file name
		GENERIC_READ,                      // desired access (read-only)
		FILE_SHARE_READ,                   // share mode
		NULL,                              // security attributes
		OPEN_EXISTING,                     // creation disposition
		FILE_ATTRIBUTE_NORMAL,             // flags and attributes
		NULL);                             // template file

	if (file.hFile == INVALID_HANDLE_VALUE)
		return std::nullopt;

	LARGE_INTEGER fileSize;
	if (!GetFileSizeEx(file.hFile, &fileSize))
	{
		CloseHandle(file.hFile);
		return std::nullopt;
	}
	file.len = static_cast<size_t>(fileSize.QuadPart);

	return file;
}

MapStatus MappedFile::Map()
{
	if (_mmap)
		return MapStatus::Success;

	HANDLE hMapping = CreateFileMapping(hFile,  // file handle
		NULL,                                   // security attributes
		PAGE_WRITECOPY,                         // protection
		0,                                      // maximum size (high-order DWORD)
		0,                                      // maximum size (low-order DWORD)
		NULL);                                  // name of the mapping object

	if (hMapping == NULL)
	{
		CloseHandle(hFile);
		return MapStatus::Error;
	}

	_mmap = static_cast<uint8_t*>(MapViewOfFile(hMapping,  // handle to the file mapping object
		FILE_MAP_COPY,                                     // desired access
		0,                                                 // file offset (high-order DWORD)
		0,                                                 // file offset (low-order DWORD)
		0));                                               // number of bytes to map (0 = entire file)

	if (_mmap == nullptr)
	{
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return MapStatus::Error;
	}

	CloseHandle(hMapping);
	CloseHandle(hFile);

	return MapStatus::Success;
}

MapStatus MappedFile::Unmap()
{
	if (_mmap)
	{
		UnmapViewOfFile(_mmap);
	}
	return MapStatus::Success;
}
#endif
