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

#pragma once

#include <string>
#include <string_view>
#include <utility>

#include "base/expected.h"

namespace bn::base {

// A shared library loaded at runtime: a .dll on Windows, a .dylib on macOS, and a .so elsewhere.
//
// The library is unloaded when the object is destroyed unless Release() hands it off, which is
// required whenever code from the library outlives the object, such as a callback that the library
// registered while it was being initialized.
//
// On Windows the library's own directory and the default search path are used to resolve its
// dependencies.
class DynamicLibrary
{
public:
	// Whether symbol lookups reach into the libraries that the loaded library links against.
	enum class SymbolScope
	{
		// GetSymbol() resolves only the symbols that the library itself defines. A library that links
		// against another library does not inherit that library's symbols.
		LibraryOnly,
		// GetSymbol() also resolves the symbols of the libraries that the library links against, which
		// is what the platform loaders do by default. Windows resolves imports by module and offers no
		// equivalent, so lookups there behave as LibraryOnly whichever scope is requested.
		LibraryAndDependencies,
	};

	// Whether the library's own symbols are available to satisfy lookups from other libraries.
	// Windows has no process-wide symbol namespace to publish them into, so this has no effect there.
	enum class SymbolVisibility
	{
		Local,
		Global,
	};

private:
	std::string m_path;
	// The loader's own name for the image, which differs from the path passed to Open() when the
	// loader searched for the library. Empty on the platforms whose GetSymbol() does not need it.
	std::string m_imagePath;
	void* m_handle;
	SymbolScope m_scope;

	DynamicLibrary(std::string path, void* handle, SymbolScope scope, std::string imagePath = {}):
		m_path(std::move(path)), m_imagePath(std::move(imagePath)), m_handle(handle), m_scope(scope)
	{}

public:
	// Load a shared library, or the platform's description of why it could not be loaded
	static expected<DynamicLibrary, std::string> Open(std::string_view path,
		SymbolScope scope = SymbolScope::LibraryOnly, SymbolVisibility visibility = SymbolVisibility::Local);

	~DynamicLibrary();

	DynamicLibrary(DynamicLibrary&& other) noexcept;
	DynamicLibrary& operator=(DynamicLibrary&& other) noexcept;

	DynamicLibrary(const DynamicLibrary&) = delete;
	DynamicLibrary& operator=(const DynamicLibrary&) = delete;

	const std::string& GetPath() const { return m_path; }

	// The address of an exported symbol, or nullptr if the library does not export it
	void* GetSymbol(const char* name) const;

	// Keep the library loaded after this object is destroyed, returning the platform handle
	void* Release();
};

}  // namespace bn::base
