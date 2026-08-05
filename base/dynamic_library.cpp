// Copyright (c) 2026 Vector 35 Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "base/dynamic_library.h"

#include <utility>

#ifdef WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#ifndef __APPLE__
#include <link.h>
#include <string.h>
#endif
#endif

namespace bn::base {

#ifdef WIN32

namespace {

std::string DescribeLastError()
{
	DWORD error = GetLastError();
	char* text = nullptr;
	DWORD length = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&text, 0, nullptr);
	if (!length)
		return "error code " + std::to_string(error);

	// The system message ends with a newline that is not wanted in the middle of a log line
	while (length && (text[length - 1] == '\n' || text[length - 1] == '\r'))
		length--;

	std::string result(text, length);
	LocalFree(text);
	return result;
}

} // unnamed namespace


expected<DynamicLibrary, std::string> DynamicLibrary::Open(
	std::string_view path, SymbolScope scope, [[maybe_unused]] SymbolVisibility visibility)
{
	std::string pathString(path);
	HMODULE handle =
		LoadLibraryExA(pathString.c_str(), NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
	if (!handle)
		return unexpected(DescribeLastError());

	return DynamicLibrary(std::move(pathString), handle, scope);
}


DynamicLibrary::~DynamicLibrary()
{
	if (m_handle)
		FreeLibrary((HMODULE)m_handle);
}


// GetProcAddress() searches the module it is given and has no way to reach that module's imports, so
// the scope is not consulted: every lookup behaves as LibraryOnly.
void* DynamicLibrary::GetSymbol(const char* name) const
{
	if (!m_handle)
		return nullptr;

	return (void*)GetProcAddress((HMODULE)m_handle, name);
}

#else // !WIN32

namespace {

#ifdef __APPLE__

// RTLD_FIRST tags the handle so that dlsym() searches only the image it was opened for
constexpr int LibraryOnlyFlag = RTLD_FIRST;

// GetSymbol() relies on RTLD_FIRST rather than on the name of the image, so nothing is resolved here
std::string ImagePath(void*, const std::string&)
{
	return std::string();
}

#else // !__APPLE__

// No dlopen() flag restricts the search on other platforms, so GetSymbol() checks each lookup
constexpr int LibraryOnlyFlag = 0;

// The name the loader knows the image by, which is what dladdr() reports for the symbols the image
// defines. It is the path dlopen() resolved, which is not the path it was given whenever it searched
// for the library. Falls back to that path when the loader will not report a name.
std::string ImagePath(void* handle, const std::string& path)
{
	link_map* map = nullptr;
	if (dlinfo(handle, RTLD_DI_LINKMAP, &map) != 0 || !map || !map->l_name || !map->l_name[0])
		return path;

	return map->l_name;
}

#endif // !__APPLE__

} // unnamed namespace


expected<DynamicLibrary, std::string> DynamicLibrary::Open(std::string_view path, SymbolScope scope, SymbolVisibility visibility)
{
	int flags = RTLD_NOW;
	flags |= visibility == SymbolVisibility::Global ? RTLD_GLOBAL : RTLD_LOCAL;
	if (scope == SymbolScope::LibraryOnly)
		flags |= LibraryOnlyFlag;

	std::string pathString(path);
	void* handle = dlopen(pathString.c_str(), flags);
	if (!handle)
	{
		const char* error = dlerror();
		return unexpected(std::string(error ? error : "dlopen failed"));
	}

	std::string imagePath = ImagePath(handle, pathString);
	return DynamicLibrary(std::move(pathString), handle, scope, std::move(imagePath));
}


DynamicLibrary::~DynamicLibrary()
{
	if (m_handle)
		dlclose(m_handle);
}


#ifdef __APPLE__

// The RTLD_FIRST flag that LibraryOnly adds to dlopen() has already limited the handle to the
// symbols that the library itself defines.
void* DynamicLibrary::GetSymbol(const char* name) const
{
	if (!m_handle)
		return nullptr;

	return dlsym(m_handle, name);
}

#else // !__APPLE__

// dlsym() searches the requested image and every image it links against, so a library that links
// against another library resolves that library's symbols as if they were its own. For LibraryOnly,
// resolve a symbol only when the image the library was loaded from is the image that defines it.
void* DynamicLibrary::GetSymbol(const char* name) const
{
	if (!m_handle)
		return nullptr;

	void* sym = dlsym(m_handle, name);
	if (!sym || m_scope == SymbolScope::LibraryAndDependencies)
		return sym;

	Dl_info info;
	if (!dladdr(sym, &info) || !info.dli_fname)
		return nullptr;

	if (strcmp(info.dli_fname, m_imagePath.c_str()) != 0)
		return nullptr;

	return sym;
}

#endif // !__APPLE__

#endif // !WIN32


DynamicLibrary::DynamicLibrary(DynamicLibrary&& other) noexcept
	: m_path(std::move(other.m_path))
	, m_imagePath(std::move(other.m_imagePath))
	, m_handle(std::exchange(other.m_handle, nullptr))
	, m_scope(other.m_scope)
{
}


DynamicLibrary& DynamicLibrary::operator=(DynamicLibrary&& other) noexcept
{
	if (this == &other)
		return *this;

	// Take over what this object held so that the library is closed at the end of the function.
	DynamicLibrary unloaded(std::move(*this));
	m_path = std::move(other.m_path);
	m_imagePath = std::move(other.m_imagePath);
	m_handle = std::exchange(other.m_handle, nullptr);
	m_scope = other.m_scope;
	return *this;
}


void* DynamicLibrary::Release()
{
	void* handle = m_handle;
	m_handle = nullptr;
	return handle;
}

}  // namespace bn::base
