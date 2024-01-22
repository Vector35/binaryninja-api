// Copyright (c) 2015-2023 Vector 35 Inc
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
#include <optional>
#include "binaryninjaapi.h"
#include "binaryninjacore.h"

using namespace BinaryNinja;


ExternalLibrary::ExternalLibrary(BNExternalLibrary* lib)
{
	m_object = lib;
}


std::string ExternalLibrary::GetName() const
{
	char* name = BNExternalLibraryGetName(m_object);
	std::string result = name;
	BNFreeString(name);
	return result;
}


Ref<ProjectFile> ExternalLibrary::GetBackingFile() const
{
	BNProjectFile* file = BNExternalLibraryGetBackingFile(m_object);
	if (!file)
		return nullptr;
	return new ProjectFile(BNNewProjectFileReference(file));
}


void ExternalLibrary::SetBackingFile(Ref<ProjectFile> file)
{
	BNExternalLibrarySetBackingFile(m_object, file ? file->m_object : nullptr);
}


ExternalLocation::ExternalLocation(BNExternalLocation* loc)
{
	m_object = loc;
}


Ref<Symbol> ExternalLocation::GetInternalSymbol()
{
	BNSymbol* sym = BNExternalLocationGetInternalSymbol(m_object);
	return new Symbol(sym);
}


std::optional<uint64_t> ExternalLocation::GetAddress()
{
	if (BNExternalLocationHasAddress(m_object))
	{
		return BNExternalLocationGetAddress(m_object);
	}
	return {};
}


std::optional<std::string> ExternalLocation::GetSymbol()
{
	if (BNExternalLocationHasSymbol(m_object))
	{
		return BNExternalLocationGetSymbol(m_object);
	}
	return {};
}


Ref<ExternalLibrary> ExternalLocation::GetExternalLibrary()
{
	BNExternalLibrary* lib = BNExternalLocationGetExternalLibrary(m_object);
	if (!lib)
		return nullptr;
	return new ExternalLibrary(BNNewExternalLibraryReference(lib));
}


bool ExternalLocation::HasAddress()
{
	return BNExternalLocationHasAddress(m_object);
}


bool ExternalLocation::HasSymbol()
{
	return BNExternalLocationHasSymbol(m_object);
}


void ExternalLocation::SetAddress(std::optional<uint64_t> address)
{
	if (address.has_value())
	{
		uint64_t addr = address.value();
		BNExternalLocationSetAddress(m_object, &addr);
	}
	else
	{
		BNExternalLocationSetAddress(m_object, nullptr);
	}
}


void ExternalLocation::SetSymbol(std::optional<std::string> symbol)
{
	if (symbol.has_value())
	{
		std::string sym = symbol.value();
		BNExternalLocationSetSymbol(m_object, sym.c_str());
	}
	else
	{
		BNExternalLocationSetSymbol(m_object, nullptr);
	}
}


void ExternalLocation::SetExternalLibrary(Ref<ExternalLibrary> library)
{
	BNExternalLocationSetExternalLibrary(m_object, library ? library->m_object : nullptr);
}


