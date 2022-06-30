#pragma once
#include <string>
#include "refcount.hpp"
#include "binaryninjacore/tempfile.h"

namespace BinaryNinja {
	class DataBuffer;
	class TemporaryFile : public CoreRefCountObject<BNTemporaryFile, BNNewTemporaryFileReference, BNFreeTemporaryFile>
	{
	  public:
		TemporaryFile();
		TemporaryFile(const DataBuffer& contents);
		TemporaryFile(const std::string& contents);
		TemporaryFile(BNTemporaryFile* file);

		bool IsValid() const { return m_object != nullptr; }
		std::string GetPath() const;
		DataBuffer GetContents();
	};
}