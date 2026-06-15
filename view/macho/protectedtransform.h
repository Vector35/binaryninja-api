#pragma once

#include "binaryninjaapi.h"
#include "machoview.h"

namespace BinaryNinja
{
	void InitProtectedTransform();

	// Apple "protected" Mach-O (legacy DSMOS, SG_PROTECTED_VERSION_1) decryptor.
	//
	// Emits a decrypted derived Mach-O image via TransformContext::SetChild, which the
	// normal Mach-O parser then consumes. Auto-chains after the Universal (fat) transform.
	// Cipher work is delegated to the always-loaded crypto plugin transforms.
	class ProtectedMachOTransform : public Transform
	{
		// A protected segment's encrypted byte range, in slice file offsets.
		struct ProtectedRange
		{
			uint64_t fileOff;
			uint64_t fileSize;
			uint64_t flagsFileOff;  // file offset of the segment command's flags field
			bool bigEndian;         // endianness of that flags field
		};

		// Lightweight Mach-O header walk used by both CanDecode and DecodeWithContext.
		// Returns false if the input does not parse as a (thin) Mach-O. Sets
		// hasProtected to true if any segment carries SG_PROTECTED_VERSION_1, and fills
		// protectedRanges with those segments' [fileoff, filesize) ranges.
		static bool ParseProtectedSegments(Ref<BinaryView> input, bool& hasProtected,
			std::vector<ProtectedRange>& protectedRanges);

		// Pure page decryptor. Decrypts the protected range [encStart, encEnd) in place
		// within image using the given cipher (selected once from the magic dword at slice
		// offset 0x3000 before any decryption — that location is itself decrypted, so it
		// must be read before the first range is processed).
		// Returns false on failure (image left untouched in the failing range).
		static bool DecryptRange(DataBuffer& image, uint64_t encStart, uint64_t encEnd,
			uint32_t cipherMagic, const std::vector<uint8_t>& key);

	public:
		ProtectedMachOTransform();

		virtual bool DecodeWithContext(Ref<TransformContext> context,
			const std::map<std::string, DataBuffer>& params) override;
		virtual bool CanDecode(Ref<BinaryView> input) const override;
	};
}
