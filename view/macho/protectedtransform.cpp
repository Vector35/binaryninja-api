#include "protectedtransform.h"
#include "machoview.h"
#include <cstring>

using namespace BinaryNinja;
using namespace std;

// The first three pages of the slice are never encrypted: XNU spares them so it can
// read the Mach-O header and load commands before the decrypting pager is wired up.
static constexpr uint64_t MACHO_PROTECTED_PAGE_SIZE = 0x1000;
static constexpr uint64_t APPLE_UNPROTECTED_HEADER_SIZE = 3 * MACHO_PROTECTED_PAGE_SIZE;  // 0x3000

// Cipher selection magic dword, read little-endian at slice offset +0x3000.
static constexpr uint32_t DSMOS_MAGIC_NONE = 0x00000000;     // not actually encrypted
static constexpr uint32_t DSMOS_MAGIC_BLOWFISH = 0x2e69cf40; // 10.6+ Blowfish (the common case)
static constexpr uint32_t DSMOS_MAGIC_AES = 0xc2286295;      // legacy 10.5- AES-256

// The DSMOS unwrap key is a fixed-length 64-byte string (the public "ourhardwork..." key).
static constexpr size_t DSMOS_KEY_SIZE = 64;

static const char* g_protectionUnwrapKeySetting = "loader.macho.protectionUnwrapKey";

bool ProtectedMachOTransform::ParseProtectedSegments(Ref<BinaryView> input, bool& hasProtected,
	vector<ProtectedRange>& protectedRanges)
{
	hasProtected = false;
	protectedRanges.clear();

	if (!input || input->GetLength() < sizeof(mach_header))
		return false;

	uint8_t magicBytes[4];
	if (input->Read(magicBytes, 0, 4) < 4)
		return false;
	uint32_t magic = *(uint32_t*)magicBytes;

	BNEndianness endianness;
	bool is64;
	if (magic == MH_MAGIC || magic == MH_MAGIC_64)
		endianness = LittleEndian;
	else if (magic == MH_CIGAM || magic == MH_CIGAM_64)
		endianness = BigEndian;
	else
		return false;  // not a thin Mach-O
	is64 = (magic == MH_MAGIC_64) || (magic == MH_CIGAM_64);

	try
	{
		BinaryReader reader(input);
		reader.SetEndianness(endianness);
		reader.Seek(16);  // magic, cputype, cpusubtype, filetype
		uint32_t ncmds = reader.Read32();
		reader.Read32();  // sizeofcmds
		reader.Read32();  // flags
		if (is64)
			reader.Read32();  // reserved

		for (uint32_t i = 0; i < ncmds; i++)
		{
			uint64_t cmdStart = reader.GetOffset();
			uint32_t cmd = reader.Read32();
			uint32_t cmdsize = reader.Read32();
			if (cmdsize < sizeof(load_command) || cmdStart + cmdsize > input->GetLength())
				return false;

			if (cmd == LC_SEGMENT || cmd == LC_SEGMENT_64)
			{
				// Require the command to be large enough to hold every segment field we
				// read below, so a truncated command can't make us parse a neighbouring
				// command's bytes as segment fields (false positive / bogus range).
				size_t segSize = (cmd == LC_SEGMENT_64) ? sizeof(segment_command_64) : sizeof(segment_command);
				if (cmdsize < segSize)
					return false;

				reader.SeekRelative(16);  // segname
				uint64_t fileOff, fileSize;
				if (cmd == LC_SEGMENT_64)
				{
					reader.Read64();  // vmaddr
					reader.Read64();  // vmsize
					fileOff = reader.Read64();
					fileSize = reader.Read64();
				}
				else
				{
					reader.Read32();  // vmaddr
					reader.Read32();  // vmsize
					fileOff = reader.Read32();
					fileSize = reader.Read32();
				}
				reader.Read32();  // maxprot
				reader.Read32();  // initprot
				reader.Read32();  // nsects
				uint64_t flagsFileOff = reader.GetOffset();
				uint32_t flags = reader.Read32();

				if (flags & SG_PROTECTED_VERSION_1)
				{
					hasProtected = true;
					protectedRanges.push_back(
						{fileOff, fileSize, flagsFileOff, endianness == BigEndian});
				}
			}

			reader.Seek(cmdStart + cmdsize);
		}
	}
	catch (ReadException&)
	{
		// Header is malformed; treat as not-a-target so the normal parser can report it.
		return false;
	}

	return true;
}


bool ProtectedMachOTransform::DecryptRange(DataBuffer& image, uint64_t encStart, uint64_t encEnd,
	uint32_t cipherMagic, const vector<uint8_t>& key)
{
	if (encEnd <= encStart)
		return true;
	if (encEnd > image.GetLength())
		return false;

	if (cipherMagic == DSMOS_MAGIC_NONE)
		return true;  // not actually encrypted; leave bytes as-is

	uint8_t* base = static_cast<uint8_t*>(image.GetData());

	if (cipherMagic == DSMOS_MAGIC_BLOWFISH)
	{
		// DSMOS chains CBC within each page but resets the IV to zero at every page
		// boundary, so we decrypt each page independently with the "Blowfish CBC"
		// transform and a fresh zero IV. The 64-byte DSMOS key exceeds Blowfish's 56-byte
		// spec maximum; our botan fork raises that cap at build time (see
		// https://github.com/vector35/botan).
		Ref<Transform> blowfish = Transform::GetByName("Blowfish CBC");
		if (!blowfish)
		{
			LogError("Mach-O Protected: 'Blowfish CBC' transform unavailable");
			return false;
		}

		DataBuffer keyBuf(key.data(), key.size());
		uint8_t zeros[8] = {0};

		for (uint64_t off = encStart; off < encEnd; off += MACHO_PROTECTED_PAGE_SIZE)
		{
			uint64_t pageLen = min<uint64_t>(MACHO_PROTECTED_PAGE_SIZE, encEnd - off);
			// Blowfish operates on 8-byte blocks; the trailing partial bytes (if any) stay clear.
			uint64_t blockLen = pageLen & ~uint64_t(7);
			if (!blockLen)
				continue;

			DataBuffer cipherPage(base + off, (size_t)blockLen);
			DataBuffer plainPage;
			map<string, DataBuffer> params;
			params["key"] = keyBuf;
			params["iv"] = DataBuffer(zeros, 8);
			if (!blowfish->Decode(cipherPage, plainPage, params) || plainPage.GetLength() != blockLen)
			{
				LogError("Mach-O Protected: Blowfish decode failed at slice offset %#" PRIx64, off);
				return false;
			}
			memcpy(base + off, plainPage.GetData(), (size_t)blockLen);
		}
		return true;
	}

	if (cipherMagic == DSMOS_MAGIC_AES)
	{
		// Legacy AES path (10.5): two AES-256-CBC operations per page with a zero IV reset
		// per half-page, key split into halves (first half-page with key[0..31], second
		// half-page with key[32..63]). CBC, not ECB: class-dump's CCCryptorCreate uses
		// options=0 (CBC), and only CBC produces a valid instruction stream here.
		Ref<Transform> aes = Transform::GetByName("AES-256 CBC");
		if (!aes || key.size() < 64)
		{
			LogError("Mach-O Protected: 'AES-256 CBC' transform unavailable or key too short");
			return false;
		}

		DataBuffer keyLow(key.data(), 32);
		DataBuffer keyHigh(key.data() + 32, 32);
		uint8_t zeros[16] = {0};
		const uint64_t halfPage = MACHO_PROTECTED_PAGE_SIZE / 2;

		for (uint64_t off = encStart; off < encEnd; off += MACHO_PROTECTED_PAGE_SIZE)
		{
			uint64_t pageLen = min<uint64_t>(MACHO_PROTECTED_PAGE_SIZE, encEnd - off);
			for (int half = 0; half < 2; half++)
			{
				uint64_t halfOff = off + (uint64_t)half * halfPage;
				if (halfOff >= off + pageLen)
					break;
				uint64_t avail = min<uint64_t>(halfPage, (off + pageLen) - halfOff);
				uint64_t blockLen = avail & ~uint64_t(15);
				if (!blockLen)
					continue;

				DataBuffer cipherHalf(base + halfOff, (size_t)blockLen);
				DataBuffer plainHalf;
				map<string, DataBuffer> params;
				params["key"] = half ? keyHigh : keyLow;
				params["iv"] = DataBuffer(zeros, 16);
				if (!aes->Decode(cipherHalf, plainHalf, params) || plainHalf.GetLength() != blockLen)
				{
					LogError("Mach-O Protected: AES decode failed at slice offset %#" PRIx64, halfOff);
					return false;
				}
				memcpy(base + halfOff, plainHalf.GetData(), (size_t)blockLen);
			}
		}
		return true;
	}

	LogError("Mach-O Protected: unknown cipher magic %#" PRIx32 " at slice offset %#" PRIx64
		"; leaving bytes encrypted", cipherMagic, APPLE_UNPROTECTED_HEADER_SIZE);
	return false;
}


ProtectedMachOTransform::ProtectedMachOTransform() :
	Transform(DecodeTransform, TransformCapabilities(TransformSupportsDetection | TransformSupportsContext),
		"Mach-O Protected", "Mach-O Protected (DSMOS)", "Container")
{
}


bool ProtectedMachOTransform::CanDecode(Ref<BinaryView> input) const
{
	// Fire for any DSMOS-protected Mach-O with a cipher we handle, regardless of whether a
	// key is configured: when the key is missing or invalid, DecodeWithContext surfaces a
	// helpful alert and falls back to loading the still-encrypted image.
	bool hasProtected;
	vector<ProtectedRange> ranges;
	if (!ParseProtectedSegments(input, hasProtected, ranges) || !hasProtected)
		return false;

	// A segment is flagged protected, but only claim the file if the cipher marker at
	// slice offset 0x3000 is one we actually handle. A None marker (0) means the segment
	// isn't really encrypted, and an unknown marker we can't decrypt — in both cases we
	// decline so the normal parser loads the file unchanged instead of emitting a
	// redundant or failed child.
	if (input->GetLength() < APPLE_UNPROTECTED_HEADER_SIZE + 4)
		return false;
	uint8_t magicBytes[4];
	if (input->Read(magicBytes, APPLE_UNPROTECTED_HEADER_SIZE, 4) < 4)
		return false;
	uint32_t magicRaw;
	memcpy(&magicRaw, magicBytes, 4);
	uint32_t magic = ToLE32(magicRaw);  // stored little-endian
	return magic == DSMOS_MAGIC_BLOWFISH || magic == DSMOS_MAGIC_AES;
}


bool ProtectedMachOTransform::DecodeWithContext(Ref<TransformContext> context,
	const map<string, DataBuffer>& params)
{
	if (!context || !context->GetInput())
		return false;

	Ref<BinaryView> input = context->GetInput();

	bool hasProtected;
	vector<ProtectedRange> ranges;
	if (!ParseProtectedSegments(input, hasProtected, ranges) || !hasProtected)
		return false;

	string unwrapKey = context->GetSettings()->Get<string>(g_protectionUnwrapKeySetting);
	vector<uint8_t> key(unwrapKey.begin(), unwrapKey.end());
	if (key.empty())
	{
		LogAlert("This Mach-O contains Apple-protected (DSMOS) segments, but no unwrap key is set.\n\n"
			"Set the '%s' setting to decrypt it; the legacy unwrap key is publicly documented online.\n\n"
			"Loading the file without decryption.", g_protectionUnwrapKeySetting);
		return false;
	}
	if (key.size() != DSMOS_KEY_SIZE)
	{
		LogAlert("The configured Mach-O protection unwrap key is invalid: expected a %zu-byte DSMOS key but got %zu bytes.\n\n"
			"The legacy unwrap key is publicly documented online.\n\n"
			"Loading the file without decryption.", DSMOS_KEY_SIZE, key.size());
		return false;
	}

	// Read the whole slice image into a buffer we can decrypt in place.
	DataBuffer image;
	image.SetSize(input->GetLength());
	if (input->Read(image.GetData(), 0, input->GetLength()) < input->GetLength())
	{
		LogError("Mach-O Protected: failed to read input image");
		return false;
	}

	// Select the cipher from the magic dword at slice offset +0x3000, read
	// little-endian, before any decryption — the first protected segment decrypts over
	// that location, so reading it per-range would see already-decrypted bytes.
	if (image.GetLength() < APPLE_UNPROTECTED_HEADER_SIZE + 4)
		return false;
	uint32_t cipherMagicRaw;
	memcpy(&cipherMagicRaw, image.GetDataAt(APPLE_UNPROTECTED_HEADER_SIZE), 4);
	uint32_t cipherMagic = ToLE32(cipherMagicRaw);  // magic is stored little-endian (class-dump OSReadLittleInt32)

	bool anyDecrypted = false;
	for (const auto& range : ranges)
	{
		// The exempt region is the first 0x3000 bytes of the SLICE, not of each
		// segment. A segment starting at/after 0x3000 is decrypted from its page
		// 0. Clamp with checked subtraction so a malformed fileOff+fileSize cannot
		// overflow.
		if (range.fileOff >= image.GetLength())
			continue;  // segment starts past EOF
		uint64_t avail = image.GetLength() - range.fileOff;
		uint64_t segFileSize = min<uint64_t>(range.fileSize, avail);
		uint64_t encStart = max<uint64_t>(range.fileOff, APPLE_UNPROTECTED_HEADER_SIZE);
		uint64_t encEnd = range.fileOff + segFileSize;  // both terms <= length; no overflow
		if (encEnd <= encStart)
			continue;  // segment lies entirely within the unprotected header

		LogInfo("Mach-O Protected: decrypting range [%#" PRIx64 ", %#" PRIx64 ") (size %#" PRIx64 ")",
			encStart, encEnd, encEnd - encStart);

		if (!DecryptRange(image, encStart, encEnd, cipherMagic, key))
		{
			LogError("Mach-O Protected: decryption failed for range [%#" PRIx64 ", %#" PRIx64
				"); falling back to original image", encStart, encEnd);
			context->SetChild(DataBuffer(), context->GetFileName() + " (decrypted)", TransformFailure,
				"Protected Mach-O decryption failed");
			return false;
		}
		anyDecrypted = true;

		// Clear SG_PROTECTED_VERSION_1 in the child's segment command. The child is now
		// decrypted, so it must NOT advertise itself as protected: the transform session
		// re-scans every emitted child, and a child that still carried the flag would match
		// CanDecode again and be re-decrypted endlessly.
		if (range.flagsFileOff + 4 <= image.GetLength())
		{
			uint8_t* fp = static_cast<uint8_t*>(image.GetData()) + range.flagsFileOff;
			uint32_t raw;
			memcpy(&raw, fp, 4);
			// Convert the file-endian flags to host order, clear the bit, convert back.
			// ToBE32/ToLE32 are their own inverse (swap-or-identity) and portable (incl. MSVC).
			uint32_t flags = range.bigEndian ? ToBE32(raw) : ToLE32(raw);
			flags &= ~uint32_t(SG_PROTECTED_VERSION_1);
			raw = range.bigEndian ? ToBE32(flags) : ToLE32(flags);
			memcpy(fp, &raw, 4);
		}
	}

	if (!anyDecrypted)
		return false;

	context->SetChild(image, context->GetFileName() + " (decrypted)", TransformSuccess, "", true);
	return true;
}


void BinaryNinja::InitProtectedTransform()
{
	Settings::Instance()->RegisterSetting(g_protectionUnwrapKeySetting,
		R"({
		"title" : "Mach-O Protection Unwrap Key",
		"type" : "string",
		"default" : "",
		"description" : "Key material used to unwrap legacy Apple-protected Mach-O segments. Empty by default; no value is shipped with the product. Decryption is enabled only when this is set. Restart Binary Ninja after changing this setting.",
		"ignore" : ["SettingsProjectScope"],
		"requiresRestart" : true
		})");

	static ProtectedMachOTransform protectedXform;
	Transform::Register(&protectedXform);
}
