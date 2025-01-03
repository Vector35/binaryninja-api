//
// Created by kat on 5/23/23.
//

#ifndef SHAREDCACHE_OBJC_H
#define SHAREDCACHE_OBJC_H

#include <binaryninjaapi.h>
#include <objectivec/objc.h>
#include "SharedCache.h"

namespace DSCObjC {
	class DSCObjCReader : public ObjCReader {
	private:
		VMReader m_reader;
		size_t m_addressSize;

	public:
		void Read(void* dest, size_t len) override;
		std::string ReadCString() override;
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

		VMReader& GetVMReader();

		DSCObjCReader(SharedCacheCore::SharedCache* cache, size_t addressSize);
	};

	class DSCObjCProcessor : public ObjCProcessor {
		std::optional<uint64_t> m_customRelativeMethodSelectorBase = std::nullopt;
		SharedCacheCore::SharedCache* m_cache;

		std::shared_ptr<ObjCReader> GetReader() override;
		void GetRelativeMethod(ObjCReader* reader, method_t& meth) override;
	
	public:
		DSCObjCProcessor(BinaryView* data, SharedCacheCore::SharedCache* cache, bool isBackedByDatabase);
		
		uint64_t GetObjCRelativeMethodBaseAddress(ObjCReader* reader) override;
	};
}
#endif //SHAREDCACHE_OBJC_H
