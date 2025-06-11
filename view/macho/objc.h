#pragma once

#include <binaryninjaapi.h>
#include <objectivec/objc.h>

namespace BinaryNinja {
	class MachoObjCReader : public ObjCReader {
	private:
		BinaryReader m_reader;

	public:
		void Read(void* dest, size_t len) override;
		std::string ReadCString(size_t maxLength = -1) override;
		uint8_t Read8() override;
		uint16_t Read16() override;
		uint32_t Read32() override;
		uint64_t Read64() override;
		int8_t ReadS8() override;
		int16_t ReadS16() override;
		int32_t ReadS32() override;
		int64_t ReadS64() override;
		uint64_t ReadPointer() override;
		uint64_t GetOffset() const override;
		void Seek(uint64_t offset) override;
		void SeekRelative(int64_t offset) override;

		MachoObjCReader(BinaryView* data);
	};

	class MachoObjCProcessor : public ObjCProcessor {
		std::shared_ptr<ObjCReader> GetReader() override;
		
	public:
		MachoObjCProcessor(BinaryView* data);

		static bool ViewHasObjCMetadata(BinaryView* data);
	};
}

