//
// Created by kat on 5/23/23.
//

/*
	This is the cross-plat file buffering logic used for SharedCache processing.
 	This is used for reading large amounts of large files in a performant manner.

 	Here be no dragons, but this code is very complex, beware.

 	We in _all_ cases memory map the files, as we hardly ever need more than a few pages per file for most intensive operations.

 	Memory Map Implementation:
 		Of interest is that on several platforms we have to account for very low file pointer limits, and when mapping
 		40+ files, these are trivially reachable.

 		We handle this with a "SelfAllocatingWeakPtr":
 			- Calling .lock() ALWAYS delivers a shared_ptr guaranteed to stay valid. This may block waiting for a free pointer
			- As soon as that lock is released, that file pointer MAY be freed if another thread wants to open a new one, and we are at our limit.
			- Calling .lock() again on this same theoretical object will then wait for another file pointer to be freeable.

	VM Implementation:


 	Since the caches we're operating on are by nature page aligned, we are able to use nice optimizations under the hood to translate
 	"VM Addresses" to their actual in-memory counterparts.

 	We do this with a page table, which is a map of page -> file offset.

 	We also implement a "VMReader" here, which is a drop-in replacement for BinaryReader that operates on the VM.
 		see "ObjC.cpp" for where this is used.

*/


#include "VM.h"
#include <utility>
#include <memory>
#include <cstring>
#include <stdio.h>
#include <filesystem>
#include <binaryninjaapi.h>

#ifdef _MSC_VER
	#include <windows.h>
#else
	#include <sys/mman.h>
	#include <fcntl.h>
	#include <stdlib.h>
	#include <sys/resource.h>
#endif

static std::atomic<uint64_t> mmapCount = 0;

uint64_t MMapCount()
{
	return mmapCount;
}

void VMShutdown() {}


std::string ResolveFilePath(BinaryNinja::Ref<BinaryNinja::BinaryView> dscView, const std::string& path)
{
	auto dscProjectFile = dscView->GetFile()->GetProjectFile();
	BinaryNinja::LogDebugF(
		"ResolveFilePath:\n    of: {}\n    path: {}\n    pfn: {}\n    pfp: {}",
		dscView->GetFile()->GetOriginalFilename(),
		path,
		dscProjectFile ? dscProjectFile->GetName() : "",
		dscProjectFile ? dscProjectFile->GetPathOnDisk() : ""
	);

	// If we're not in a project, just return the path we were given
	if (!dscProjectFile)
	{
		return path;
	}

	// TODO: do we need to support looking in subfolders?
	// Replace project file path on disk with project file name for resolution
	std::string projectFilePathOnDisk = dscProjectFile->GetPathOnDisk();
	std::string originalFilePathOnDisk = dscView->GetFile()->GetOriginalFilename();
	std::string cleanPath = path;
	if (auto pindex = cleanPath.find(projectFilePathOnDisk); pindex != std::string::npos)
	{
		cleanPath.replace(pindex, projectFilePathOnDisk.size(), dscProjectFile->GetName());
	}
	else if (auto oindex = cleanPath.find(originalFilePathOnDisk); oindex != std::string::npos)
	{
		BinaryNinja::Ref<BinaryNinja::ProjectFile> originalProjectFile = dscProjectFile->GetProject()->GetFileByPathOnDisk(originalFilePathOnDisk);
		if (!originalProjectFile)
		{
			BinaryNinja::LogErrorF("Failed to resolve file path for {}: original file {} not found", path, originalFilePathOnDisk);
			return path;
		}
		cleanPath.replace(oindex, originalFilePathOnDisk.size(), originalProjectFile->GetName());
	}

	size_t lastSlashPos = cleanPath.find_last_of("/\\");
	std::string fileName;

	if (lastSlashPos != std::string::npos) {
		fileName = cleanPath.substr(lastSlashPos + 1);
	} else {
		fileName = cleanPath;
	}

	auto project = dscProjectFile->GetProject();
	auto dscProjectFolder = dscProjectFile->GetFolder();
	for (const auto& file : project->GetFiles())
	{
		auto fileFolder = file->GetFolder();
		bool isSibling = false;
		if (!dscProjectFolder && !fileFolder)
		{
			// Both top-level
			isSibling = true;
		}
		else if (dscProjectFolder && fileFolder)
		{
			// Have same parent folder
			isSibling = dscProjectFolder->GetId() == fileFolder->GetId();
		}

		if (isSibling && file->GetName() == fileName)
		{
			return file->GetPathOnDisk();
		}
	}

	BinaryNinja::LogErrorF("Failed to resolve file path for {}", path);

	// If we couldn't find a sibling filename, just return the path we were given
	return path;
}


void MMAP::Map()
{
	if (mapped)
		return;
#ifdef _MSC_VER
	LARGE_INTEGER fileSize;
	if (!GetFileSizeEx(hFile, &fileSize))
	{
		// Handle error
		CloseHandle(hFile);
		return;
	}
	len = static_cast<size_t>(fileSize.QuadPart);

	HANDLE hMapping = CreateFileMapping(
		hFile,                       // file handle
		NULL,                        // security attributes
		PAGE_WRITECOPY,              // protection
		0,                           // maximum size (high-order DWORD)
		0,                           // maximum size (low-order DWORD)
		NULL);                       // name of the mapping object

	if (hMapping == NULL)
	{
		// Handle error
		CloseHandle(hFile);
		return;
	}

	_mmap = static_cast<uint8_t*>(MapViewOfFile(
		hMapping,                    // handle to the file mapping object
		FILE_MAP_COPY,         		 // desired access
		0,                           // file offset (high-order DWORD)
		0,                           // file offset (low-order DWORD)
		0));                         // number of bytes to map (0 = entire file)

	if (_mmap == nullptr)
	{
		// Handle error
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return;
	}

	mapped = true;

	CloseHandle(hMapping);
	CloseHandle(hFile);

#else
	fseek(fd, 0L, SEEK_END);
	len = ftell(fd);
	fseek(fd, 0L, SEEK_SET);

	void *result = mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fileno(fd), 0u);
	if (result == MAP_FAILED)
	{
		// Handle error
		return;
	}

	_mmap = static_cast<uint8_t*>(result);
	mapped = true;
#endif
}

void MMAP::Unmap()
{
#ifdef _MSC_VER
	if (_mmap)
	{
		UnmapViewOfFile(_mmap);
		mapped = false;
	}
#else
	if (mapped)
	{
		munmap(_mmap, len);
		mapped = false;
	}
#endif
}

FileAccessorCache& FileAccessorCache::Shared()
{
	static FileAccessorCache& shared = *new FileAccessorCache;
	return shared;
};

FileAccessorCache::FileAccessorCache() = default;

void FileAccessorCache::SetCacheSize(uint64_t cacheSize)
{
	m_cacheSize = cacheSize;
	EvictFromCacheIfNeeded();
}

void FileAccessorCache::RecordAccess(const std::string& path)
{
	auto it = m_accessors.find(path);
	if (it == m_accessors.end())
		return;

	// Move the entry for `path` to the end of `m_leastRecentlyOpened`.
	m_leastRecentlyOpened.splice(m_leastRecentlyOpened.end(), m_leastRecentlyOpened, it->second.second);
}

void FileAccessorCache::EvictFromCacheIfNeeded()
{
	std::lock_guard lock(m_mutex);
	while (m_accessors.size() > m_cacheSize)
	{
		m_accessors.erase(m_leastRecentlyOpened.front());
		m_leastRecentlyOpened.pop_front();
	}
}

std::shared_ptr<LazyMappedFileAccessor> FileAccessorCache::OpenLazily(
	const uint64_t sessionID, const std::string& path,
	std::function<void(std::shared_ptr<MMappedFileAccessor>)> postAllocationRoutine)
{
	std::lock_guard lock(m_mutex);
	if (auto it = m_lazyAccessors.find(path); it != m_lazyAccessors.end())
	{
		RecordAccess(path);
		return it->second;
	}

	auto accessor = std::make_shared<LazyMappedFileAccessor>(path,
		[=, postAllocationRoutine = std::move(postAllocationRoutine)](
			const std::string& path) {
			auto accessor = Open(sessionID, path);
			if (postAllocationRoutine)
			{
				postAllocationRoutine(accessor);
			}
			return accessor;
		});

	m_lazyAccessors.insert_or_assign(path, accessor);
	return accessor;
}

std::shared_ptr<MMappedFileAccessor> FileAccessorCache::Open(
	const uint64_t sessionID, const std::string& path)
{
	EvictFromCacheIfNeeded();

	mmapCount++;
	auto accessor = std::shared_ptr<MMappedFileAccessor>(new MMappedFileAccessor(path),
		[this](MMappedFileAccessor* accessor) { Close(accessor); });

	std::lock_guard lock(m_mutex);
	auto [it, inserted] = m_accessors.insert({path, {accessor, m_leastRecentlyOpened.end()}});
	if (inserted)
	{
		m_leastRecentlyOpened.push_back(path);
		it->second.second = std::prev(it->second.second);
	}
	else
	{
		RecordAccess(path);
	}

	return accessor;
}

void FileAccessorCache::Close(MMappedFileAccessor* accessor)
{
	mmapCount--;
	delete accessor;
}

std::shared_ptr<LazyMappedFileAccessor> MMappedFileAccessor::Open(
	const uint64_t sessionID, const std::string& path,
	std::function<void(std::shared_ptr<MMappedFileAccessor>)> postAllocationRoutine)
{
	return FileAccessorCache::Shared().OpenLazily(sessionID, path, std::move(postAllocationRoutine));
}

void MMappedFileAccessor::InitialVMSetup()
{
	static std::once_flag once;
	std::call_once(once, []{
		// check for BN_SHAREDCACHE_FP_MAX
		// if it exists, set maxFPLimit to that value
		unsigned long long maxFPLimit = 0;
		if (auto env = getenv("BN_SHAREDCACHE_FP_MAX"); env)
		{
			// FIXME behav on 0 here is unintuitive, '0123' will interpret as octal and be 83 according to manpage. meh.
			maxFPLimit = strtoull(env, nullptr, 0);
			if (maxFPLimit < 10)
			{
				BinaryNinja::LogWarn("BN_SHAREDCACHE_FP_MAX set to below 10. A value of at least 10 is recommended for performant analysis on SharedCache Binaries.");
			}
			if (maxFPLimit == 0)
			{
				BinaryNinja::LogError("BN_SHAREDCACHE_FP_MAX set to 0. Adjusting to 1");
				maxFPLimit = 1;
			}
		}
		else
		{
#ifdef _MSC_VER
			// It is not _super_ clear what the max file pointer limit is on windows,
			// 	but to my understanding, we are using the windows API to map files,
			// 	so we should have at least 2^24;
			// kind of funny to me that windows would be the most effecient OS to
			// parallelize sharedcache processing on in terms of FP usage concerns
			maxFPLimit = 0x1000000;
#else
			// The soft file descriptor limit on Linux and Mac is a lot lower than
			// on Windows (1024 for Linux, 256 for Mac). Recent iOS shared caches
			// have 60+ files which may not leave much headroom if a user opens
			// more than one at a time. Attempt to increase the file descriptor
			// limit to 1024, and limit ourselves to caching half of them as a
			// memory vs performance trade-off (closing and re-opening a file
			// requires parsing and applying the slide information again).
			constexpr rlim_t TargetFileDescriptorLimit = 1024;
			struct rlimit rlim;
			getrlimit(RLIMIT_NOFILE, &rlim);
			unsigned long long previousLimit = rlim.rlim_cur;
			if (rlim.rlim_cur < TargetFileDescriptorLimit)
			{
				rlim.rlim_cur = std::min(TargetFileDescriptorLimit, rlim.rlim_max);
				if (setrlimit(RLIMIT_NOFILE, &rlim) < 0)
				{
					perror("setrlimit(RLIMIT_NOFILE)");
					rlim.rlim_cur = previousLimit;
				}
			}
			maxFPLimit = rlim.rlim_cur / 2;
#endif
		}
		BinaryNinja::LogInfo("Shared Cache processing initialized with a max file descriptor limit of %lld", maxFPLimit);
		FileAccessorCache::Shared().SetCacheSize(maxFPLimit);
	});
}


MMappedFileAccessor::MMappedFileAccessor(const std::string& path) : m_path(path)
{
#ifdef _MSC_VER
	m_mmap.hFile = CreateFile(
		path.c_str(),              // file name
		GENERIC_READ,              // desired access (read-only)
        FILE_SHARE_READ,                         // share mode
		NULL,                      // security attributes
		OPEN_EXISTING,             // creation disposition
		FILE_ATTRIBUTE_NORMAL,     // flags and attributes
		NULL);                     // template file

	if (m_mmap.hFile == INVALID_HANDLE_VALUE)
	{
		// BNLogInfo("Couldn't read file at %s", path.c_str());
		throw MissingFileException();
	}

#else
#ifdef ABORT_FAILURES
	if (path.empty())
	{
		cerr << "Path is empty." << endl;
		abort();
	}
#endif
	m_mmap.fd = fopen(path.c_str(), "r");
	if (m_mmap.fd == nullptr)
	{
		BNLogError("Serious VM Error: Couldn't read file at %s", path.c_str());

#ifndef _MSC_VER
		try {
			throw BinaryNinja::ExceptionWithStackTrace("Unable to Read file");
		}
		catch (ExceptionWithStackTrace &ex)
		{
			BNLogError("%s", ex.m_stackTrace.c_str());
			BNLogError("Error: %d (%s)", errno, strerror(errno));
		}
#endif
		throw MissingFileException();
	}
#endif

	m_mmap.Map();
}

MMappedFileAccessor::~MMappedFileAccessor()
{
	// BNLogInfo("Unmapping %s", m_path.c_str());
	m_mmap.Unmap();

#ifdef _MSC_VER
	if (m_mmap.hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_mmap.hFile);
	}
#else
	if (m_mmap.fd != nullptr)
	{
		fclose(m_mmap.fd);
	}
#endif
}

void MMappedFileAccessor::WritePointer(size_t address, size_t pointer)
{
	*(size_t*)&m_mmap._mmap[address] = pointer;
}

template <typename T>
T MMappedFileAccessor::Read(size_t address)
{
	T result;
	Read(&result, address, sizeof(T));
	return result;
}

std::string MMappedFileAccessor::ReadNullTermString(size_t address)
{
	if (address > m_mmap.len)
		return "";
	auto start = m_mmap._mmap + address;
	auto end = m_mmap._mmap + m_mmap.len;
	auto nul = std::find(start, end, 0);
	return std::string(start, nul);
}

uint8_t MMappedFileAccessor::ReadUChar(size_t address)
{
	return Read<uint8_t>(address);
}

int8_t MMappedFileAccessor::ReadChar(size_t address)
{
	return Read<int8_t>(address);
}

uint16_t MMappedFileAccessor::ReadUShort(size_t address)
{
	return Read<uint16_t>(address);
}

int16_t MMappedFileAccessor::ReadShort(size_t address)
{
	return Read<int16_t>(address);
}

uint32_t MMappedFileAccessor::ReadUInt32(size_t address)
{
	return Read<uint32_t>(address);
}

int32_t MMappedFileAccessor::ReadInt32(size_t address)
{
	return Read<int32_t>(address);
}

uint64_t MMappedFileAccessor::ReadULong(size_t address)
{
	return Read<uint64_t>(address);
}

int64_t MMappedFileAccessor::ReadLong(size_t address)
{
	return Read<int64_t>(address);
}

BinaryNinja::DataBuffer MMappedFileAccessor::ReadBuffer(size_t address, size_t length)
{
	if (m_mmap.len <= length || address > m_mmap.len - length)
		throw MappingReadException();

	return BinaryNinja::DataBuffer(&m_mmap._mmap[address], length);
}

std::pair<const uint8_t*, const uint8_t*> MMappedFileAccessor::ReadSpan(size_t address, size_t length)
{
	if (address > m_mmap.len)
		throw MappingReadException();
	if (address + length > m_mmap.len)
		throw MappingReadException();
	const uint8_t* data = (&(((uint8_t*)m_mmap._mmap)[address]));
	return {data, data + length};
}


void MMappedFileAccessor::Read(void* dest, size_t address, size_t length)
{
	if (m_mmap.len <= length || address > m_mmap.len - length)
		throw MappingReadException();

	memcpy(dest, &m_mmap._mmap[address], length);
}


VM::VM(size_t pageSize, bool safe) : m_pageSize(pageSize), m_safe(safe)
{
}

VM::~VM()
{
}


void VM::MapPages(BinaryNinja::Ref<BinaryNinja::BinaryView> dscView, uint64_t sessionID, size_t vm_address, size_t fileoff, size_t size, const std::string& filePath, std::function<void(std::shared_ptr<MMappedFileAccessor>)> postAllocationRoutine)
{
	// The mappings provided for shared caches will always be page aligned.
	// We can use this to our advantage and gain considerable performance via page tables.
	// This could probably be sped up if c++ were avoided?
	// We want to create a map of page -> file offset

	if (vm_address % m_pageSize != 0 || size % m_pageSize != 0)
	{
		throw MappingPageAlignmentException();
	}

	auto accessor =
		MMappedFileAccessor::Open(sessionID, ResolveFilePath(dscView, filePath), std::move(postAllocationRoutine));
	auto [it, inserted] = m_map.insert_or_assign({vm_address, vm_address + size}, PageMapping(std::move(accessor), fileoff));
	if (m_safe && !inserted)
	{
		BNLogWarn("Remapping page 0x%zx (f: 0x%zx)", vm_address, fileoff);
		throw MappingCollisionException();
	}
}

std::pair<PageMapping, size_t> VM::MappingAtAddress(size_t address)
{
	if (auto it = m_map.find(address); it != m_map.end())
	{
		// The PageMapping object returned contains the page, and more importantly, the file pointer (there can be
		// multiple in newer caches) This is relevant for reading out the data in the rest of this file.
		// The second item in the returned pair is the offset of `address` within the file.
		auto& range = it->first;
		auto& mapping = it->second;
		return {mapping, mapping.fileOffset + (address - range.start)};
	}

	throw MappingReadException();
}


bool VM::AddressIsMapped(uint64_t address)
{
	auto it = m_map.find(address);
	return it != m_map.end();
}


uint64_t VMReader::ReadULEB128(size_t limit)
{
	uint64_t result = 0;
	int bit = 0;
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	auto fileCursor = mapping.second;
	auto fileLimit = fileCursor + (limit - m_cursor);
	auto fa = mapping.first.fileAccessor->lock();
	auto* fileBuff = (uint8_t*)fa->Data();
	do
	{
		if (fileCursor >= fileLimit)
			return -1;
		uint64_t slice = ((uint64_t*)&((fileBuff)[fileCursor]))[0] & 0x7f;
		if (bit > 63)
			return -1;
		else
		{
			result |= (slice << bit);
			bit += 7;
		}
	} while (((uint64_t*)&(fileBuff[fileCursor++]))[0] & 0x80);
	fa->Data(); // prevent deallocation of the fileAccessor as we're operating on the raw data buffer
	return result;
}


int64_t VMReader::ReadSLEB128(size_t limit)
{
	uint8_t cur;
	int64_t value = 0;
	size_t shift = 0;

	auto mapping = m_vm->MappingAtAddress(m_cursor);
	auto fileCursor = mapping.second;
	auto fileLimit = fileCursor + (limit - m_cursor);
	auto fa = mapping.first.fileAccessor->lock();
	auto* fileBuff = (uint8_t*)fa->Data();

	while (fileCursor < fileLimit)
	{
		cur = ((uint64_t*)&((fileBuff)[fileCursor]))[0];
		fileCursor++;
		value |= (cur & 0x7f) << shift;
		shift += 7;
		if ((cur & 0x80) == 0)
			break;
	}
	value = (value << (64 - shift)) >> (64 - shift);
	fa->Data(); // prevent deallocation of the fileAccessor as we're operating on the raw data buffer
	return value;
}

std::string VM::ReadNullTermString(size_t address)
{
	auto mapping = MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadNullTermString(mapping.second);
}

uint8_t VM::ReadUChar(size_t address)
{
	auto mapping = MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadUChar(mapping.second);
}

int8_t VM::ReadChar(size_t address)
{
	auto mapping = MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadChar(mapping.second);
}

uint16_t VM::ReadUShort(size_t address)
{
	auto mapping = MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadUShort(mapping.second);
}

int16_t VM::ReadShort(size_t address)
{
	auto mapping = MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadShort(mapping.second);
}

uint32_t VM::ReadUInt32(size_t address)
{
	auto mapping = MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadUInt32(mapping.second);
}

int32_t VM::ReadInt32(size_t address)
{
	auto mapping = MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadInt32(mapping.second);
}

uint64_t VM::ReadULong(size_t address)
{
	auto mapping = MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadULong(mapping.second);
}

int64_t VM::ReadLong(size_t address)
{
	auto mapping = MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadLong(mapping.second);
}

BinaryNinja::DataBuffer VM::ReadBuffer(size_t addr, size_t length)
{
	auto mapping = MappingAtAddress(addr);
	return mapping.first.fileAccessor->lock()->ReadBuffer(mapping.second, length);
}


void VM::Read(void* dest, size_t addr, size_t length)
{
	auto mapping = MappingAtAddress(addr);
	mapping.first.fileAccessor->lock()->Read(dest, mapping.second, length);
}

VMReader::VMReader(std::shared_ptr<VM> vm, size_t addressSize) : m_vm(vm), m_cursor(0), m_addressSize(addressSize) {}


void VMReader::Seek(size_t address)
{
	m_cursor = address;
}

void VMReader::SeekRelative(size_t offset)
{
	m_cursor += offset;
}

std::string VMReader::ReadCString(size_t address)
{
	auto mapping = m_vm->MappingAtAddress(address);
	return mapping.first.fileAccessor->lock()->ReadNullTermString(mapping.second);
}

uint8_t VMReader::ReadUChar(size_t address)
{
	auto mapping = m_vm->MappingAtAddress(address);
	m_cursor = address + 1;
	return mapping.first.fileAccessor->lock()->ReadUChar(mapping.second);
}

int8_t VMReader::ReadChar(size_t address)
{
	auto mapping = m_vm->MappingAtAddress(address);
	m_cursor = address + 1;
	return mapping.first.fileAccessor->lock()->ReadChar(mapping.second);
}

uint16_t VMReader::ReadUShort(size_t address)
{
	auto mapping = m_vm->MappingAtAddress(address);
	m_cursor = address + 2;
	return mapping.first.fileAccessor->lock()->ReadUShort(mapping.second);
}

int16_t VMReader::ReadShort(size_t address)
{
	auto mapping = m_vm->MappingAtAddress(address);
	m_cursor = address + 2;
	return mapping.first.fileAccessor->lock()->ReadShort(mapping.second);
}

uint32_t VMReader::ReadUInt32(size_t address)
{
	auto mapping = m_vm->MappingAtAddress(address);
	m_cursor = address + 4;
	return mapping.first.fileAccessor->lock()->ReadUInt32(mapping.second);
}

int32_t VMReader::ReadInt32(size_t address)
{
	auto mapping = m_vm->MappingAtAddress(address);
	m_cursor = address + 4;
	return mapping.first.fileAccessor->lock()->ReadInt32(mapping.second);
}

uint64_t VMReader::ReadULong(size_t address)
{
	auto mapping = m_vm->MappingAtAddress(address);
	m_cursor = address + 8;
	return mapping.first.fileAccessor->lock()->ReadULong(mapping.second);
}

int64_t VMReader::ReadLong(size_t address)
{
	auto mapping = m_vm->MappingAtAddress(address);
	m_cursor = address + 8;
	return mapping.first.fileAccessor->lock()->ReadLong(mapping.second);
}


size_t VMReader::ReadPointer(size_t address)
{
	if (m_addressSize == 8)
		return ReadULong(address);
	else if (m_addressSize == 4)
		return ReadUInt32(address);

	// no idea what horrible arch we have, should probably die here.
	return 0;
}


size_t VMReader::ReadPointer()
{
	if (m_addressSize == 8)
		return Read64();
	else if (m_addressSize == 4)
		return Read32();

	return 0;
}

BinaryNinja::DataBuffer VMReader::ReadBuffer(size_t length)
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += length;
	return mapping.first.fileAccessor->lock()->ReadBuffer(mapping.second, length);
}

BinaryNinja::DataBuffer VMReader::ReadBuffer(size_t addr, size_t length)
{
	auto mapping = m_vm->MappingAtAddress(addr);
	m_cursor = addr + length;
	return mapping.first.fileAccessor->lock()->ReadBuffer(mapping.second, length);
}

void VMReader::Read(void* dest, size_t length)
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += length;
	mapping.first.fileAccessor->lock()->Read(dest, mapping.second, length);
}

void VMReader::Read(void* dest, size_t addr, size_t length)
{
	auto mapping = m_vm->MappingAtAddress(addr);
	m_cursor = addr + length;
	mapping.first.fileAccessor->lock()->Read(dest, mapping.second, length);
}


uint8_t VMReader::Read8()
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += 1;
	return mapping.first.fileAccessor->lock()->ReadUChar(mapping.second);
}

int8_t VMReader::ReadS8()
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += 1;
	return mapping.first.fileAccessor->lock()->ReadChar(mapping.second);
}

uint16_t VMReader::Read16()
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += 2;
	return mapping.first.fileAccessor->lock()->ReadUShort(mapping.second);
}

int16_t VMReader::ReadS16()
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += 2;
	return mapping.first.fileAccessor->lock()->ReadShort(mapping.second);
}

uint32_t VMReader::Read32()
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += 4;
	return mapping.first.fileAccessor->lock()->ReadUInt32(mapping.second);
}

int32_t VMReader::ReadS32()
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += 4;
	return mapping.first.fileAccessor->lock()->ReadInt32(mapping.second);
}

uint64_t VMReader::Read64()
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += 8;
	return mapping.first.fileAccessor->lock()->ReadULong(mapping.second);
}

int64_t VMReader::ReadS64()
{
	auto mapping = m_vm->MappingAtAddress(m_cursor);
	m_cursor += 8;
	return mapping.first.fileAccessor->lock()->ReadLong(mapping.second);
}
