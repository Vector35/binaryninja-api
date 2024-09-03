#include <algorithm>
#include <cstring>
#include <cctype>
#include <list>
#include <string.h>
#include <inttypes.h>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <type_traits>
#include <utility>
#include "peview.h"
#include "coffview.h"
#include "teview.h"

#define STRING_READ_CHUNK_SIZE 32

using namespace BinaryNinja;
using namespace std;


static PEViewType* g_peViewType = nullptr;
static const char* imageDirName[] = { "exportTable", "importTable", "resourceTable", "exceptionTable", "certificateTable", "baseRelocationTable", "debug", "architecture", "globalPtr", "tlsTable", "loadConfigTable", "boundImport", "iat", "delayImportDescriptor", "clrRuntimeHeader", "reserved"};

void BinaryNinja::InitPEViewType()
{
	static PEViewType type;
	BinaryViewType::Register(&type);
	g_peViewType = &type;
}

// String representation of Rich header object types
static const string kProdId_C = "[ C ]";
static const string kProdId_CPP = "[C++]";
static const string kProdId_RES = "[RES]";
static const string kProdId_IMP = "[IMP]";
static const string kProdId_EXP = "[EXP]";
static const string kProdId_ASM = "[ASM]";
static const string kProdId_LNK = "[LNK]";
static const string kProdId_UNK = "[ ? ]";

static const std::map<uint16_t, string> ProductIdMap = {
	{0x0000, kProdId_UNK},
	{0x0002, kProdId_IMP},
	{0x0004, kProdId_LNK},
	{0x0006, kProdId_RES},
	{0x000A, kProdId_C},
	{0x000B, kProdId_CPP},
	{0x000F, kProdId_ASM},
	{0x0015, kProdId_C},
	{0x0016, kProdId_CPP},
	{0x0019, kProdId_IMP},
	{0x001C, kProdId_C},
	{0x001D, kProdId_CPP},
	{0x003D, kProdId_LNK},
	{0x003F, kProdId_EXP},
	{0x0040, kProdId_ASM},
	{0x0045, kProdId_RES},
	{0x005A, kProdId_LNK},
	{0x005C, kProdId_EXP},
	{0x005D, kProdId_IMP},
	{0x005E, kProdId_RES},
	{0x005F, kProdId_C},
	{0x0060, kProdId_CPP},
	{0x006D, kProdId_C},
	{0x006E, kProdId_CPP},
	{0x0078, kProdId_LNK},
	{0x007A, kProdId_EXP},
	{0x007B, kProdId_IMP},
	{0x007C, kProdId_RES},
	{0x007D, kProdId_ASM},
	{0x0083, kProdId_C},
	{0x0084, kProdId_CPP},
	{0x0091, kProdId_LNK},
	{0x0092, kProdId_EXP},
	{0x0093, kProdId_IMP},
	{0x0094, kProdId_RES},
	{0x0095, kProdId_ASM},
	{0x009A, kProdId_RES},
	{0x009B, kProdId_EXP},
	{0x009C, kProdId_IMP},
	{0x009D, kProdId_LNK},
	{0x009E, kProdId_ASM},
	{0x00AA, kProdId_C},
	{0x00AB, kProdId_CPP},
	{0x00C9, kProdId_RES},
	{0x00CA, kProdId_EXP},
	{0x00CB, kProdId_IMP},
	{0x00CC, kProdId_LNK},
	{0x00CD, kProdId_ASM},
	{0x00CE, kProdId_C},
	{0x00CF, kProdId_CPP},
	{0x00DB, kProdId_RES},
	{0x00DC, kProdId_EXP},
	{0x00DD, kProdId_IMP},
	{0x00DE, kProdId_LNK},
	{0x00DF, kProdId_ASM},
	{0x00E0, kProdId_C},
	{0x00E1, kProdId_CPP},
	{0x00FF, kProdId_RES},
	{0x0100, kProdId_EXP},
	{0x0101, kProdId_IMP},
	{0x0102, kProdId_LNK},
	{0x0103, kProdId_ASM},
	{0x0104, kProdId_C},
	{0x0105, kProdId_CPP}
};


// Mapping of Rich header build number to version strings
static const std::map<uint16_t, const string> ProductMap = {
	// Source: https://github.com/dishather/richprint/blob/master/comp_id.txt
	{0x0000, "Imported Functions"},
	{0x0684, "VS97 v5.0 SP3 cvtres 5.00.1668"},
	{0x06B8, "VS98 v6.0 cvtres build 1720"},
	{0x06C8, "VS98 v6.0 SP6 cvtres build 1736"},
	{0x1C87, "VS97 v5.0 SP3 link 5.10.7303"},
	{0x5E92, "VS2015 v14.0 UPD3 build 24210"},
	{0x5E95, "VS2015 UPD3 build 24213"},

	// http://bytepointer.com/articles/the_microsoft_rich_header.htm
	{0x0BEC, "VS2003 v7.1 Free Toolkit .NET build 3052"},
	{0x0C05, "VS2003 v7.1 .NET build 3077"},
	{0x0FC3, "VS2003 v7.1 | Windows Server 2003 SP1 DDK build 4035"},
	{0x1C83, "MASM 6.13.7299"},
	{0x178E, "VS2003 v7.1 SP1 .NET build 6030"},
	{0x1FE8, "VS98 v6.0 RTM/SP1/SP2 build 8168"},
	{0x1FE9, "VB 6.0/SP1/SP2 build 8169"},
	{0x20FC, "MASM 6.14.8444"},
	{0x20FF, "VC++ 6.0 SP3 build 8447"},
	{0x212F, "VB 6.0 SP3 build 8495"},
	{0x225F, "VS 6.0 SP4 build 8799"},
	{0x2263, "MASM 6.15.8803"},
	{0x22AD, "VB 6.0 SP4 build 8877"},
	{0x2304, "VB 6.0 SP5 build 8964"},
	{0x2306, "VS 6.0 SP5 build 8966"},
	//  {0x2346, "MASM 6.15.9030 (VS.NET 7.0 BETA 1)"},
	{0x2346, "VS 7.0 2000 Beta 1 build 9030"},
	{0x2354, "VS 6.0 SP5 Processor Pack build 9044"},
	{0x2426, "VS2001 v7.0 Beta 2 build 9254"},
	{0x24FA, "VS2002 v7.0 .NET build 9466"},
	{0x2636, "VB 6.0 SP6 / VC++ build 9782"},
	{0x26E3, "VS2002 v7.0 SP1 build 9955"},
	{0x520D, "VS2013 v12.[0,1] build 21005"},
	{0x521E, "VS2008 v9.0 build 21022"},
	{0x56C7, "VS2015 v14.0 build 22215"},
	{0x59F2, "VS2015 v14.0 build 23026"},
	{0x5BD2, "VS2015 v14.0 UPD1 build 23506"},
	{0x5D10, "VS2015 v14.0 UPD2 build 23824"},
	{0x5E97, "VS2015 v14.0 UPD3.1 build 24215"},
	{0x7725, "VS2013 v12.0 UPD2 build 30501"},
	{0x766F, "VS2010 v10.0 build 30319"},
	{0x7809, "VS2008 v9.0 SP1 build 30729"},
	{0x797D, "VS2013 v12.0 UPD4 build 31101"},
	{0x9D1B, "VS2010 v10.0 SP1 build 40219"},
	{0x9EB5, "VS2013 v12.0 UPD5 build 40629"},
	{0xC497, "VS2005 v8.0 (Beta) build 50327"},
	{0xC627, "VS2005 v8.0 | VS2012 v11.0 build 50727"},
	{0xC751, "VS2012 v11.0 Nov CTP build 51025"},
	{0xC7A2, "VS2012 v11.0 UPD1 build 51106"},
	{0xEB9B, "VS2012 v11.0 UPD2 build 60315"},
	{0xECC2, "VS2012 v11.0 UPD3 build 60610"},
	{0xEE66, "VS2012 v11.0 UPD4 build 61030"},
	{0x5E9A, "VS2015 v14.0 build 24218"},
	{0x61BB, "VS2017 v14.1 build 25019"},

	// https://dev.to/yumetodo/list-of-mscver-and-mscfullver-8nd
	{0x2264, "VS 6 [SP5,SP6] build 8804"},
	{0x23D8, "Windows XP SP1 DDK"},
	{0x0883, "Windows Server 2003 DDK"},
	{0x08F4, "VS2003 v7.1 .NET Beta build 2292"},
	{0x9D76, "Windows Server 2003 SP1 DDK (for AMD64)"},
	{0x9E9F, "VS2005 v8.0 Beta 1 build 40607"},
	{0xC427, "VS2005 v8.0 Beta 2 build 50215"},
	{0xC490, "VS2005 v8.0 build 50320"},
	{0x50E2, "VS2008 v9.0 Beta 2 build 20706"},
	{0x501A, "VS2010 v10.0 Beta 1 build 20506"},
	{0x520B, "VS2010 v10.0 Beta 2 build 21003"},
	{0x5089, "VS2013 v12.0 Preview build 20617"},
	{0x515B, "VS2013 v12.0 RC build 20827"},
	{0x527A, "VS2013 v12.0 Nov CTP build 21114"},
	{0x7674, "VS2013 v12.0 UPD2 RC build 30324"},
	{0x63A3, "VS2017 v15.3.3 build 25507"},
	{0x63C6, "VS2017 v15.4.4 build 25542"},
	{0x63CB, "VS2017 v15.4.5 build 25547"},

	// https://walbourn.github.io/visual-studio-2015-update-2/
	{0x5D6E, "VS2015 v14.0 UPD2 build 23918"},

	// https://walbourn.github.io/visual-studio-2017/
	{0x61B9, "VS2017 v15.[0,1] build 25017"},
	{0x63A2, "VS2017 v15.2 build 25019"},

	// https://walbourn.github.io/vs-2017-15-5-update/
	{0x64E6, "VS2017 v15 build 25830"},
	{0x64E7, "VS2017 v15.5.2 build 25831"},
	{0x64EA, "VS2017 v15.5.[3,4] build 25834"},
	{0x64EB, "VS2017 v15.5.[5,6,7] build 25835"},

	// https://walbourn.github.io/vs-2017-15-6-update/
	{0x6610, "VS2017 v15.6.[0,1,2] build 26128"},
	{0x6611, "VS2017 v15.6.[3,4] build 26129"},
	{0x6613, "VS2017 v15.6.6 build 26131"},
	{0x6614, "VS2017 v15.6.7 build 26132"},

	// https://devblogs.microsoft.com/visualstudio/visual-studio-2017-update/
	{0x6723, "VS2017 v15.1 build 26403"},

	// https://walbourn.github.io/vs-2017-15-7-update/
	{0x673C, "VS2017 v15.7.[0,1] build 26428"},
	{0x673D, "VS2017 v15.7.2 build 26429"},
	{0x673E, "VS2017 v15.7.3 build 26430"},
	{0x673F, "VS2017 v15.7.4 build 26431"},
	{0x6741, "VS2017 v15.7.5 build 26433"},

	// https://walbourn.github.io/visual-studio-2019/
	{0x6B74, "VS2019 v16.0.0 build 27508"},

	// https://walbourn.github.io/vs-2017-15-8-update/
	{0x6866, "VS2017 v15.8.0 build 26726"},
	{0x6869, "VS2017 v15.8.4 build 26729"},
	{0x686A, "VS2017 v15.8.9 build 26730"},
	{0x686C, "VS2017 v15.8.5 build 26732"},

	// https://walbourn.github.io/vs-2017-15-9-update/
	{0x698F, "VS2017 v15.9.[0,1] build 27023"},
	{0x6990, "VS2017 v15.9.2 build 27024"},
	{0x6991, "VS2017 v15.9.4 build 27025"},
	{0x6992, "VS2017 v15.9.5 build 27026"},
	{0x6993, "VS2017 v15.9.7 build 27027"},
	{0x6996, "VS2017 v15.9.11 build 27030"},
	{0x6997, "VS2017 v15.9.12 build 27031"},
	{0x6998, "VS2017 v15.9.14 build 27032"},
	{0x699A, "VS2017 v15.9.16 build 27034"},

	// https://walbourn.github.io/vs-2019-update-3/
	{0x6DC9, "VS2019 v16.3.2 UPD3 build 28105"},

	// https://walbourn.github.io/visual-studio-2013-update-3/
	{0x7803, "VS2013 v12.0 UPD3 build 30723"},

	// experimentation
	{0x685B, "VS2017 v15.8.? build 26715"},

	{27508, "VS2019 v16.0.0 build 27508"},

	// https://walbourn.github.io/vs-2019-update-1/
	{27702, "VS2019 v16.1.2 build 27702"},

	// https://walbourn.github.io/vs-2019-update-2/
	{27905, "VS2019 v16.2.3 build 27905"},

	// https://walbourn.github.io/vs-2019-update-3/
	{28105, "VS2019 v16.3.2 build 28105"},

	// https://walbourn.github.io/vs-2019-update-4/
	{28314, "VS2019 v16.4.0 build 28314"},
	{28315, "VS2019 v16.4.3 build 28315"},
	{28316, "VS2019 v16.4.4 build 28316"},
	{28319, "VS2019 v16.4.6 build 28319"},

	// https://walbourn.github.io/vs-2019-update-5/
	{28610, "VS2019 v16.5.0 build 28610"},
	{28611, "VS2019 v16.5.1 build 28611"},
	{28612, "VS2019 v16.5.2 build 28612"},
	{28614, "VS2019 v16.5.4 build 28614"},

	// https://walbourn.github.io/vs-2019-update-6/
	{28805, "VS2019 v16.6.0 build 28805"},
	{28806, "VS2019 v16.6.1 build 28806"},

	// https://walbourn.github.io/vs-2019-update-7/
	{29110, "VS2019 v16.7.0 build 29110"},
	{29111, "VS2019 v16.7.1 build 29111"},
	{29112, "VS2019 v16.7.5 build 29112"},

	// https://walbourn.github.io/vs-2019-update-8/
	{29333, "VS2019 v16.8.0 build 29333"},
	{29334, "VS2019 v16.8.2 build 29334"},
	{29335, "VS2019 v16.8.3 build 29335"},
	{29336, "VS2019 v16.8.4 build 29336"},
	{29337, "VS2019 v16.8.5 build 29337"},

	// https://walbourn.github.io/vs-2019-update-9/
	{29910, "VS2019 v16.9.0 build 29910"},
	{29911, "VS2019 v16.9.1 build 29911"},
	{29912, "VS2019 v16.9.2 build 29912"},
	{29913, "VS2019 v16.9.3 build 29913"},
	{29914, "VS2019 v16.9.4 build 29914"},
	{29915, "VS2019 v16.9.5 build 29915"},

	// https://walbourn.github.io/vs-2019-update-10/
	{30037, "VS2019 v16.10.0 build 30037"},
	{30038, "VS2019 v16.10.2 build 30038"},
	{30040, "VS2019 v16.10.4 build 30040"},

	// https://walbourn.github.io/vs-2019-update-11/
	{30133, "VS2019 v16.11.0 build 30133"},
	{30136, "VS2019 v16.11.4 build 30136"},
	{30137, "VS2019 v16.11.6 build 30137"},
	{30138, "VS2019 v16.11.8 build 30138"},
	{30139, "VS2019 v16.11.9 build 30139"},
	{30140, "VS2019 v16.11.10 build 30140"},
	{30141, "VS2019 v16.11.11 build 30141"},
	{30142, "VS2019 v16.11.12 build 30142"},
	{30143, "VS2019 v16.11.13 build 30143"},
	{30145, "VS2019 v16.11.14 build 30145"},
	{30146, "VS2019 v16.11.16 build 30146"},
	{30147, "VS2019 v16.11.19 build 30147"},
	{30148, "VS2019 v16.11.24 build 30148"},

	// https://walbourn.github.io/visual-studio-2022/
	{30705, "VS2022 17.0.0 build 30705"},
	{30706, "VS2022 17.0.2 build 30706"},
	{30709, "VS2022 17.0.5 build 30709"},

	// https://walbourn.github.io/vs-2022-update-1/
	{31104, "VS2022 17.1.0 build 31104"},
	{31105, "VS2022 17.1.2 build 31105"},
	{31106, "VS2022 17.1.4 build 31106"},
	{31107, "VS2022 17.1.6 build 31107"},

	// https://walbourn.github.io/vs-2022-update-2/
	{31328, "VS2022 v17.2.0 build 31328"},
	{31329, "VS2022 v17.2.1 build 31329"},
	{31332, "VS2022 v17.2.5 build 31332"},

	// https://walbourn.github.io/vs-2022-update-3/
	{31629, "VS2022 v17.3.0 build 31629"},
	{31630, "VS2022 v17.3.4 build 31630"},

	// https://walbourn.github.io/vs-2022-update-4/
	{31933, "VS2022 17.4.0 build 31933"},
	{31935, "VS2022 17.4.2 build 31935"},
	{31937, "VS2022 17.4.3 build 31937"},
	{31942, "VS2022 17.4.5 build 31942"},

	// https://walbourn.github.io/vs-2022-update-5/
	{32215, "VS2022 17.5.0 build 32215"},
	{32216, "VS2022 17.5.3 build 32216"},
	{32217, "VS2022 17.5.4 build 32217"},
};

static const string kUnknownProduct = "<unknown>";

// Returns a stringified Rich header object type given a product id
const string &GetRichObjectType(uint16_t prodId) {

  auto it = ProductIdMap.find(prodId);
  if (it != ProductIdMap.end()) {
    return it->second;
  } else {
    return kProdId_UNK;
  }
}

// Returns a stringified Rich header product name given a build number
const string &GetRichProductName(uint16_t buildNum) {

  auto it = ProductMap.find(buildNum);
  if (it != ProductMap.end()) {
    return it->second;
  } else {
    return kUnknownProduct;
  }
}

static string GetDebugTypeName(int type)
{
	switch (type)
	{
		case IMAGE_DEBUG_TYPE_UNKNOWN: return "debug_type_unknown";
		case IMAGE_DEBUG_TYPE_COFF: return "debug_type_coff";
		case IMAGE_DEBUG_TYPE_CODEVIEW: return "debug_type_codeview";
		case IMAGE_DEBUG_TYPE_FPO: return "debug_type_fpo";
		case IMAGE_DEBUG_TYPE_MISC: return "debug_type_misc";
		case IMAGE_DEBUG_TYPE_EXCEPTION: return "debug_type_exception";
		case IMAGE_DEBUG_TYPE_FIXUP: return "debug_type_fixup";
		case IMAGE_DEBUG_TYPE_OMAP_TO_SRC: return "debug_type_omap_to_src";
		case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC: return "debug_type_omap_from_src";
		case IMAGE_DEBUG_TYPE_BORLAND: return "debug_type_borland";
		case IMAGE_DEBUG_TYPE_RESERVED10: return "debug_type_reserved10";
		case IMAGE_DEBUG_TYPE_CLSID: return "debug_type_clsid";
		case IMAGE_DEBUG_TYPE_VC_FEATURE: return "debug_type_vc_feature";
		case IMAGE_DEBUG_TYPE_POGO: return "debug_type_pogo";
		case IMAGE_DEBUG_TYPE_ILTCG: return "debug_type_iltcg";
		case IMAGE_DEBUG_TYPE_MPX: return "debug_type_mpx";
		case IMAGE_DEBUG_TYPE_REPRO: return "debug_type_repro";
		case IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS: return "debug_type_ex_dll_characteristics";
		default: return string("debug_type_unknown(") + string(std::to_string(type)) + string(")");
	}
}


PEView::PEView(BinaryView* data, bool parseOnly) : BinaryView("PE", data->GetFile(), data), m_parseOnly(parseOnly)
{
	CreateLogger("BinaryView");
	m_logger = CreateLogger("BinaryView.PEView");
	m_backedByDatabase = data->GetFile()->IsBackedByDatabase("PE");
}


bool PEView::Init()
{
	std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
	map<string, size_t> usedSectionNames;

	BinaryReader reader(GetParentView(), LittleEndian);
	Ref<Platform> platform;

	Ref<Settings> settings;
	PEHeader header;
	PEOptionalHeader opt;
	memset(&opt, 0, sizeof(opt));

	try
	{
		// Read PE offset
		reader.Seek(0x3c);
		uint32_t peOfs = reader.Read32();

		// Read Rich header
		vector<pair<uint32_t, uint32_t>> richValues;
		const uint32_t richHeaderBase = 0x80;
		if (peOfs > richHeaderBase)
		{
			reader.Seek(richHeaderBase);
			for (uint32_t i = 0; i < ((peOfs - richHeaderBase) / 8); i++)
			{
				uint32_t var1 = reader.Read32();
				uint32_t var2 = reader.Read32();
				richValues.push_back({var1, var2});
			}
		}

		// Read PE header
		reader.Seek(peOfs);
		header.magic = reader.Read32();
		header.machine = reader.Read16();
		header.sectionCount = reader.Read16();
		header.timestamp = reader.Read32();
		header.coffSymbolTable = reader.Read32();
		header.coffSymbolCount = reader.Read32();
		header.optionalHeaderSize = reader.Read16();
		header.characteristics = reader.Read16();
		m_logger->LogDebug(
			"PEHeader:\n"
			"\tmagic:              0x%08x\n"
			"\tmachine:            0x%04x\n"
			"\tsectionCount:       0x%04x\n"
			"\ttimestamp:          0x%08x\n"
			"\tcoffSymbolTable:    0x%08x\n"
			"\tcoffSymbolCount:    0x%08x\n"
			"\toptionalHeaderSize: 0x%04x\n"
			"\tcharacteristics:    0x%04x %s, %s, %s\n",
			header.magic,
			header.machine,
			header.sectionCount,
			header.timestamp,
			header.coffSymbolTable,
			header.coffSymbolCount,
			header.optionalHeaderSize,
			header.characteristics,
			header.characteristics & 1 ? "No Relocations" : "",
			header.characteristics & 2 ? "Executable" : "",
			header.characteristics & 0x2000 ? "Dll" : "Unknown");

		uint64_t optionalHeaderOffset = reader.GetOffset();
		// Read optional header
		opt.magic = reader.Read16();
		opt.majorLinkerVersion = reader.Read8();
		opt.minorLinkerVersion = reader.Read8();
		opt.sizeOfCode = reader.Read32();
		opt.sizeOfInitData = reader.Read32();
		opt.sizeOfUninitData = reader.Read32();
		opt.addressOfEntry = reader.Read32();
		opt.baseOfCode = reader.Read32();

		m_logger->LogDebug(
			"PEOptionalHeader:\n"
			"\tmagic               %04x (%s-bit)\n"
			"\tmajorLinkerVersion: %02x\n"
			"\tminorLinkerVersion: %02x\n"
			"\tsizeOfCode:         %08x\n"
			"\tsizeOfInitData:     %08x\n"
			"\tsizeOfUninitData:   %08x\n"
			"\taddressOfEntry:     %08x\n"
			"\tbaseOfCode:         %08x\n",
			opt.magic, opt.magic == 0x10b ? "32" : opt.magic == 0x20b ? "64" : "??",
			opt.majorLinkerVersion,
			opt.minorLinkerVersion,
			opt.sizeOfCode,
			opt.sizeOfInitData,
			opt.sizeOfUninitData,
			opt.addressOfEntry,
			opt.baseOfCode);

		if (opt.magic == 0x10b)  // 32-bit
		{
			m_is64 = false;
			opt.baseOfData = reader.Read32();
			opt.imageBase = reader.Read32();
			opt.sectionAlign = reader.Read32();
			opt.fileAlign = reader.Read32();
			opt.majorOSVersion = reader.Read16();
			opt.minorOSVersion = reader.Read16();
			opt.majorImageVersion = reader.Read16();
			opt.minorImageVersion = reader.Read16();
			opt.majorSubsystemVersion = reader.Read16();
			opt.minorSubsystemVersion = reader.Read16();
			opt.win32Version = reader.Read32();
			opt.sizeOfImage = reader.Read32();
			opt.sizeOfHeaders = reader.Read32();
			opt.checksum = reader.Read32();
			opt.subsystem = reader.Read16();
			opt.dllCharacteristics = reader.Read16();
			opt.sizeOfStackReserve = reader.Read32();
			opt.sizeOfStackCommit = reader.Read32();
			opt.sizeOfHeapReserve = reader.Read32();
			opt.sizeOfHeapCommit = reader.Read32();
			opt.loaderFlags = reader.Read32();
			opt.dataDirCount = reader.Read32();
		}
		else if (opt.magic == 0x20b) // 64-bit
		{
			m_is64 = true;
			opt.baseOfData = 0;
			opt.imageBase = reader.Read64();
			opt.sectionAlign = reader.Read32();
			opt.fileAlign = reader.Read32();
			opt.majorOSVersion = reader.Read16();
			opt.minorOSVersion = reader.Read16();
			opt.majorImageVersion = reader.Read16();
			opt.minorImageVersion = reader.Read16();
			opt.majorSubsystemVersion = reader.Read16();
			opt.minorSubsystemVersion = reader.Read16();
			opt.win32Version = reader.Read32();
			opt.sizeOfImage = reader.Read32();
			opt.sizeOfHeaders = reader.Read32();
			opt.checksum = reader.Read32();
			opt.subsystem = reader.Read16();
			opt.dllCharacteristics = reader.Read16();
			opt.sizeOfStackReserve = reader.Read64();
			opt.sizeOfStackCommit = reader.Read64();
			opt.sizeOfHeapReserve = reader.Read64();
			opt.sizeOfHeapCommit = reader.Read64();
			opt.loaderFlags = reader.Read32();
			opt.dataDirCount = reader.Read32();
		}
		else
		{
			m_logger->LogError("invalid PE optional header type");
			return false;
		}

		map<string, Ref<Metadata>> metadataMap = {
			{"Machine",               new Metadata((uint64_t) header.machine)},
			{"Characteristics",       new Metadata((uint64_t) header.characteristics)},
			{"Magic",                 new Metadata((uint64_t) opt.magic)},
			{"MajorLinkerVersion",    new Metadata((uint64_t) opt.majorLinkerVersion)},
			{"MinorLinkerVersion",    new Metadata((uint64_t) opt.minorLinkerVersion)},
			{"MajorOSVersion",        new Metadata((uint64_t) opt.majorOSVersion)},
			{"MinorOSVersion",        new Metadata((uint64_t) opt.minorOSVersion)},
			{"MajorImageVersion",     new Metadata((uint64_t) opt.majorImageVersion)},
			{"MajorImageVersion",     new Metadata((uint64_t) opt.majorImageVersion)},
			{"MinorSubsystemVersion", new Metadata((uint64_t) opt.minorSubsystemVersion)},
			{"MinorSubsystemVersion", new Metadata((uint64_t) opt.minorSubsystemVersion)},
			{"Subsystem",             new Metadata((uint64_t) opt.subsystem)},
			{"DllCharacteristics",    new Metadata((uint64_t) opt.dllCharacteristics)},
		};

		Ref<Metadata> metadata = new Metadata(metadataMap);

		platform = g_peViewType->RecognizePlatform(header.machine, LittleEndian, GetParentView(), metadata);

		// set m_arch early so the to make it available for the demangler
		m_arch = platform ? platform->GetArchitecture() : g_peViewType->GetArchitecture(header.machine, LittleEndian);
		if (!m_arch)
		{
			// There is no registered architecture for this header.machine likely malware doing something funky
			// assume x86/x86_64
			m_arch = g_peViewType->GetArchitecture(opt.magic == 0x20b ? 0x8664 : 0x14c, LittleEndian);
			m_logger->LogWarn(
				"This binary doesn't specify its architecture. Defaulting to x86. If this isn't correct please "
				"re-open with 'with options' and specify the correct architecture.");
		}
		if (!platform)
			platform = g_peViewType->GetPlatform(opt.subsystem, m_arch);
		if (!platform)
			platform = m_arch->GetStandalonePlatform();

		m_imageBase = m_peImageBase = opt.imageBase;
		SetOriginalImageBase(m_peImageBase);
		m_entryPoint = opt.addressOfEntry;

		Ref<Settings> viewSettings = Settings::Instance();
		m_extractMangledTypes = viewSettings->Get<bool>("analysis.extractTypesFromMangledNames", this);
		m_simplifyTemplates = viewSettings->Get<bool>("analysis.types.templateSimplifier", this);

		settings = GetLoadSettings(GetTypeName());
		if (settings)
		{
			if (settings->Contains("loader.imageBase"))
				m_imageBase = settings->Get<uint64_t>("loader.imageBase", this);

			if (settings->Contains("loader.platform"))
			{
				Ref<Platform> platformOverride = Platform::GetByName(settings->Get<string>("loader.platform", this));
				if (platformOverride)
				{
					platform = platformOverride;
					m_arch = platform->GetArchitecture();
				}
			}
		}

		// Apply architecture and platform
		if (!m_arch)
		{
			switch (header.machine)
			{
			case 0x14c:
				m_logger->LogError("Support for PE architecture 'x86' is not present");
				break;
			case 0x1c0:
				m_logger->LogError("Support for PE architecture 'armv7' is not present");
				break;
			case 0x8664:
				m_logger->LogError("Support for PE architecture 'x86_64' is not present");
				break;
			case 0xaa64:
				#ifndef DEMO_EDITION
				m_logger->LogError("Support for PE architecture 'arm64' is not present");
				#else
				m_logger->LogError("Binary Ninja free does not support PE architecture 'arm64'. "
								   "Purchase Binary Ninja to unlock all features.");
				#endif
				break;
			default:
				m_logger->LogError("PE architecture '0x%x' is not supported", header.machine);
				break;
			}
			return false;
		}

		platform = platform->GetAssociatedPlatformByAddress(m_entryPoint);
		SetDefaultPlatform(platform);
		SetDefaultArchitecture(platform->GetArchitecture());

		bool fileAlignmentValid = ((opt.fileAlign >= 0x200) && (opt.fileAlign <= 0x10000)) ? (opt.fileAlign & (opt.fileAlign - 1)) == 0 : false;
		uint32_t resolvedSectionAlignment = fileAlignmentValid ? opt.sectionAlign : (header.machine == IMAGE_FILE_MACHINE_IA64) ? 0x2000 : 0x1000;
		uint32_t resolvedFileAlignment = fileAlignmentValid ? opt.fileAlign : 0x200;
		if (!fileAlignmentValid)
			m_logger->LogWarn("PE has invalid FileAlignment with value: 0x%x", opt.fileAlign);
		m_sizeOfHeaders = opt.sizeOfHeaders;
		if (opt.sizeOfHeaders % resolvedFileAlignment)
			m_sizeOfHeaders = (opt.sizeOfHeaders + resolvedFileAlignment) & ~(resolvedFileAlignment - 1);
		m_relocatable = (opt.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) > 0;
		m_logger->LogDebug(
			"OptionalHeaderComponents:\n"
			"\topt.baseOfData            %08lx\n"
			"\topt.imageBase             %016lx\n"
			"\topt.sectionAlign          %08lx\n"
			"\topt.fileAlign             %08lx\n"
			"\topt.majorOSVersion        %04hx\n"
			"\topt.minorOSVersion        %04hx\n"
			"\topt.majorImageVersion     %04hx\n"
			"\topt.minorImageVersion     %04hx\n"
			"\topt.majorSubsystemVersion %04hx\n"
			"\topt.minorSubsystemVersion %04hx\n"
			"\topt.win32Version          %08lx\n"
			"\topt.sizeOfImage           %08lx\n"
			"\topt.sizeOfHeaders         %08lx\n"
			"\topt.checksum              %08lx\n"
			"\topt.subsystem             %04hx\n"
			"\topt.dllCharacteristics    %04hx\n"
			"\topt.sizeOfStackReserve    %016lx\n"
			"\topt.sizeOfStackCommit     %016lx\n"
			"\topt.sizeOfHeapReserve     %016lx\n"
			"\topt.sizeOfHeapCommit      %016lx\n"
			"\topt.loaderFlags           %08lx\n"
			"\topt.dataDirCount          %016llx\n"
			"\topt.imageBase             %016llx\n"
			"\topt.sizeOfHeaders         %08lx\n"
			"\topt.addressOfEntry        %08lx\n",
			opt.baseOfData,
			opt.imageBase,
			opt.sectionAlign,
			opt.fileAlign,
			opt.majorOSVersion,
			opt.minorOSVersion,
			opt.majorImageVersion,
			opt.minorImageVersion,
			opt.majorSubsystemVersion,
			opt.minorSubsystemVersion,
			opt.win32Version,
			opt.sizeOfImage,
			opt.sizeOfHeaders,
			opt.checksum,
			opt.subsystem,
			opt.dllCharacteristics,
			opt.sizeOfStackReserve,
			opt.sizeOfStackCommit,
			opt.sizeOfHeapReserve,
			opt.sizeOfHeapCommit,
			opt.loaderFlags,
			opt.dataDirCount,
			opt.imageBase,
			opt.sizeOfHeaders,
			opt.addressOfEntry);

		// PE Optional Header Validation
		if (opt.dataDirCount > 16)
		{
			m_logger->LogWarn("PE Optional Header: NumberOfRvaAndSizes exceeds allowable size. Truncating count: %d to 16.",
				opt.dataDirCount);
			opt.dataDirCount = 16;
		}

		// Read data directories
		for (uint32_t i = 0; i < opt.dataDirCount; i++)
		{
			PEDataDirectory dir;
			dir.virtualAddress = reader.Read32();
			dir.size = reader.Read32();
			m_dataDirs.push_back(dir);
		}

		// Add extra segment to hold header so that it can be viewed.  This must be first so
		// that real sections take priority.
		if (header.sectionCount)
			AddAutoSegment(m_imageBase, m_sizeOfHeaders, 0, m_sizeOfHeaders, SegmentReadable);
		else
		{
			uint64_t sizeOfImage = opt.sizeOfImage;
			if (opt.sizeOfImage % resolvedSectionAlignment)
				sizeOfImage = (opt.sizeOfImage + resolvedSectionAlignment) & ~(resolvedSectionAlignment - 1);
			uint64_t dataLength = GetParentView()->GetEnd();
			dataLength = std::min(std::max((uint64_t)m_sizeOfHeaders, sizeOfImage), dataLength);
			AddAutoSegment(m_imageBase, sizeOfImage, 0, dataLength, SegmentReadable);
		}
		reader.Seek(optionalHeaderOffset + header.optionalHeaderSize);
		// Read sections
		BinaryReader sectionNameReader(GetParentView(), LittleEndian);
		for (uint16_t i = 0; i < header.sectionCount; i++)
		{
			PESection section;
			m_logger->LogDebug("Offset: %lx\n", reader.GetOffset());
			char name[9];
			memset(name, 0, sizeof(name));
			reader.Read(name, 8);
			string resolvedName = name;
			if (name[0] == '/' && header.coffSymbolTable)
			{
				uint32_t stringTableBase = header.coffSymbolTable + (header.coffSymbolCount * 18);
				errno = 0;
				uint32_t offset = strtoul(name+1, nullptr, 10);
				if (errno == 0 && offset > 0 && stringTableBase + offset < GetParentView()->GetEnd())
				{
					sectionNameReader.Seek(stringTableBase + offset);
					resolvedName = sectionNameReader.ReadCString();
				}
			}
			section.name = resolvedName;
			if (section.name == ".reloc")
				m_relocatable = true;

			section.virtualSize = reader.Read32();
			section.virtualAddress = reader.Read32();
			section.sizeOfRawData = reader.Read32();
			section.pointerToRawData = reader.Read32();
			if (fileAlignmentValid && (section.pointerToRawData & (resolvedFileAlignment - 1)))
			{
				m_logger->LogWarn("PE section[%u] violates file alignment: pointerToRawData: 0x%x. Aligning to 0x%x.", i,
					section.pointerToRawData, resolvedFileAlignment);
				section.pointerToRawData &= ~(resolvedFileAlignment - 1);
			}
			section.pointerToRelocs = reader.Read32();
			section.pointerToLineNumbers = reader.Read32();
			section.relocCount = reader.Read16();
			section.lineNumberCount = reader.Read16();
			section.characteristics = reader.Read32();

			if (section.virtualSize == 0)
			{
				section.virtualSize = section.sizeOfRawData;
			}
			m_sections.push_back(section);

			uint32_t flags = 0;
			if (section.characteristics & 0x80000000)
				flags |= SegmentWritable;
			if (section.characteristics & 0x40000000)
				flags |= SegmentReadable;
			if (section.characteristics & 0x20000000)
				flags |= SegmentExecutable;
			if (section.characteristics & 0x80)
				flags |= SegmentContainsData;
			if (section.characteristics & 0x40)
				flags |= SegmentContainsData;
			if (section.characteristics & 0x20)
				flags |= SegmentContainsCode;


			m_logger->LogDebug(
				"Section [%d]\n"
				"\tsection.name                  %s\n"
				"\tsection.virtualSize:          %lx\n"
				"\tsection.virtualAddress:       %lx\n"
				"\tsection.sizeOfRawData:        %lx\n"
				"\tsection.pointerToRawData:     %lx\n"
				"\tsection.pointerToRelocs:      %lx\n"
				"\tsection.pointerToLineNumbers: %lx\n"
				"\tsection.relocCount:           %hx\n"
				"\tsection.lineNumberCount:      %hx\n"
				"\tsection.characteristics:      %lx\n"
				"\tsection.virtualSize:          %lx\n",
				i, section.name.c_str(),
				section.virtualAddress,
				section.sizeOfRawData,
				section.pointerToRawData,
				section.pointerToRelocs,
				section.pointerToLineNumbers,
				section.relocCount,
				section.lineNumberCount,
				section.characteristics);

			m_logger->LogDebug("Segment: Vaddr: %08" PRIx64 " Vsize: %08" PRIx64 " Offset: %08" PRIx64 " Rawsize: %08" PRIx64
				" %c%c%c %s\n",
				section.virtualAddress + m_imageBase,
				section.virtualSize,
				section.pointerToRawData,
				section.sizeOfRawData,
				(flags & SegmentExecutable) > 0 ? 'x':'-',
				(flags & SegmentReadable) > 0 ? 'r':'-',
				(flags & SegmentWritable) > 0 ? 'w':'-',
				section.name.c_str());

			if (!section.virtualSize)
				continue;

			AddAutoSegment(section.virtualAddress + m_imageBase, section.virtualSize, section.pointerToRawData, section.sizeOfRawData, flags);

			BNSectionSemantics semantics = DefaultSectionSemantics;
			uint32_t pFlags = flags & 0x7;
			if (pFlags == (SegmentReadable | SegmentExecutable))
				semantics = ReadOnlyCodeSectionSemantics;
			else if (pFlags == SegmentReadable)
				semantics = ReadOnlyDataSectionSemantics;
			else if (pFlags == (SegmentReadable | SegmentWritable))
				semantics = ReadWriteDataSectionSemantics;

			// FIXME: For now everride semantics for well known section names and warn about the semantic promotion
			static map<string, BNSectionSemantics> promotedSectionSemantics =
			{
				{"text", ReadOnlyCodeSectionSemantics},
				{"code", ReadOnlyCodeSectionSemantics},
				{"rdata", ReadOnlyDataSectionSemantics},
				{"data", ReadWriteDataSectionSemantics},
				{"bss", ReadWriteDataSectionSemantics}
			};
			string shortName = section.name;
			if (shortName.length() && shortName[0] == '.')
				shortName.erase(shortName.begin());
			transform(shortName.begin(), shortName.end(), shortName.begin(), ::tolower);
			if (auto itr = promotedSectionSemantics.find(shortName); (itr != promotedSectionSemantics.end()) && (itr->second != semantics))
			{
				m_logger->LogInfo("%s section semantics have been promoted to facilitate analysis.", section.name.c_str());
				semantics = itr->second;
			}

			auto emplaced = usedSectionNames.emplace(section.name, 1);
			if (emplaced.second)
			{
				AddAutoSection(section.name, section.virtualAddress + m_imageBase, section.virtualSize, semantics);
			}
			else
			{
				stringstream ss;
				ss << section.name << "_" << ++emplaced.first->second;
				AddAutoSection(ss.str(), section.virtualAddress + m_imageBase, section.virtualSize, semantics);
			}
		}

		// Finished for parse only mode
		if (m_parseOnly)
			return true;

		// Add the entry point as a function if the architecture is supported
		if (m_entryPoint)
			AddEntryPointForAnalysis(platform, m_imageBase + m_entryPoint);

		// Create various PE header yypes

		// Create MS-DOS Header Type
		StructureBuilder dosHeaderBuilder;
		dosHeaderBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 2), "e_magic");
		dosHeaderBuilder.AddMember(Type::IntegerType(2, false), "e_cblp");
		dosHeaderBuilder.AddMember(Type::IntegerType(2, false), "e_cp");
		dosHeaderBuilder.AddMember(Type::IntegerType(2, false), "e_crlc");
		dosHeaderBuilder.AddMember(Type::IntegerType(2, false), "e_cparhdr");
		dosHeaderBuilder.AddMember(Type::IntegerType(2, false), "e_minalloc");
		dosHeaderBuilder.AddMember(Type::IntegerType(2, false), "e_maxalloc");
		dosHeaderBuilder.AddMember(Type::IntegerType(2, false), "e_ss");
		dosHeaderBuilder.AddMember(Type::IntegerType(2, false), "e_sp");
		dosHeaderBuilder.AddMember(Type::IntegerType(2, false), "e_csum");
		dosHeaderBuilder.AddMember(Type::IntegerType(2, false), "e_ip");
		dosHeaderBuilder.AddMember(Type::IntegerType(2, false), "e_cs");
		dosHeaderBuilder.AddMember(Type::IntegerType(2, false), "e_lfarlc");
		dosHeaderBuilder.AddMember(Type::IntegerType(2, false), "e_ovno");
		dosHeaderBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 8), "e_res1");
		dosHeaderBuilder.AddMember(Type::IntegerType(2, false), "e_oemid");
		dosHeaderBuilder.AddMember(Type::IntegerType(2, false), "e_oeminfo");
		dosHeaderBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 20), "e_res2");
		dosHeaderBuilder.AddMember(Type::IntegerType(4, false), "e_lfanew");

		Ref<Structure> dosHeaderStruct = dosHeaderBuilder.Finalize();
		Ref<Type> dosHeaderType = Type::StructureType(dosHeaderStruct);
		QualifiedName dosHeaderName = string("DOS_Header");
		string dosHeaderTypeId = Type::GenerateAutoTypeId("pe", dosHeaderName);
		QualifiedName dosHeaderTypeName = DefineType(dosHeaderTypeId, dosHeaderName, dosHeaderType);
		DefineDataVariable(m_imageBase, Type::NamedType(this, dosHeaderTypeName));
		DefineAutoSymbol(new Symbol(DataSymbol, "__dos_header", m_imageBase, NoBinding));
		DefineDataVariable(m_imageBase + 0x40, Type::VoidType());
		DefineAutoSymbol(new Symbol(DataSymbol, "__dos_stub", m_imageBase + 0x40, NoBinding));

		// Create Rich Header Type
		// TODO move decoded rich info to comments once comments work with linear view
		if (richValues.size() >= 4)
		{
			bool validRichHeader = false;
			uint32_t xorKey = richValues[0].second;
			uint32_t entryIdx;
			vector<uint64_t> richMetadataLookupIdentifiers;
			vector<string> richMetadataLookupNames;
			for (const auto& [id, name] : ProductMap)
			{
				richMetadataLookupIdentifiers.push_back(id);
				richMetadataLookupNames.push_back(name);
			}
			StoreMetadata("RichHeaderLookupIdentifiers", new Metadata(richMetadataLookupIdentifiers), true);
			StoreMetadata("RichHeaderLookupNames", new Metadata(richMetadataLookupNames), true);

			vector<Ref<Metadata>> richMetadata;
			for (entryIdx = 0; entryIdx < richValues.size(); entryIdx++)
			{
				if ((richValues[entryIdx].first == 0x68636952) && (richValues[entryIdx].second == xorKey))
				{
					validRichHeader = true;
					break;
				}

				richValues[entryIdx].first ^= xorKey;
				richValues[entryIdx].second ^= xorKey;
				if (entryIdx > 1) // Skip the first 2 entries as they don't contain interesting information
				{
					map<string, Ref<Metadata>> entryMetadata = {
						{string("ObjectTypeValue"), new Metadata((uint64_t)richValues[entryIdx].first >> 16)},
						{string("ObjectTypeName"), new Metadata(GetRichObjectType(richValues[entryIdx].first >> 16))},
						{string("ObjectVersionValue"), new Metadata((uint64_t)richValues[entryIdx].first & 0xffff)},
						{string("ObjectVersionName"), new Metadata(GetRichProductName(richValues[entryIdx].first & 0xffff))},
						{string("ObjectCount"), new Metadata((uint64_t)richValues[entryIdx].second)}
						};
					richMetadata.push_back(new Metadata(entryMetadata));
				}
				if (!entryIdx && richValues[entryIdx].first != 0x536e6144)
					break;
			}

			if (validRichHeader)
			{
				StoreMetadata("RichHeader", new Metadata(richMetadata), true);
				StructureBuilder richHeaderBuilder;
				richHeaderBuilder.AddMember(Type::IntegerType(4, false), "e_magic__DanS");
				richHeaderBuilder.AddMember(Type::ArrayType(Type::IntegerType(4, false), 3), "e_align");

				for (uint32_t i = 2; i < entryIdx; i++)
				{
					stringstream ss;
					ss << "e_entry_id" << std::dec << i-2 << "__" << std::hex << std::setw(8) << std::setfill('0') << richValues[i].first;
					richHeaderBuilder.AddMember(Type::IntegerType(4, false), ss.str());
					ss.str("");
					ss.clear();
					ss << "e_entry_count" << std::dec << i-2 << "__" << richValues[i].second;
					richHeaderBuilder.AddMember(Type::IntegerType(4, false), ss.str());
				}

				richHeaderBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 4), "e_magic");
				richHeaderBuilder.AddMember(Type::IntegerType(4, false), "e_checksum");

				Ref<Structure> richHeaderStruct = richHeaderBuilder.Finalize();
				Ref<Type> richHeaderType = Type::StructureType(richHeaderStruct);
				QualifiedName richHeaderName = string("Rich_Header");
				string richHeaderTypeId = Type::GenerateAutoTypeId("pe", richHeaderName);
				QualifiedName richHeaderTypeName = DefineType(richHeaderTypeId, richHeaderName, richHeaderType);
				DefineDataVariable(m_imageBase + richHeaderBase, Type::NamedType(this, richHeaderTypeName));
				DefineAutoSymbol(new Symbol(DataSymbol, "__rich_header", m_imageBase + richHeaderBase, NoBinding));
			}
		}

		// Create COFF Header Type
		EnumerationBuilder coffHeaderMachineBuilder;
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_UNKNOWN", IMAGE_FILE_MACHINE_UNKNOWN);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_AM33", IMAGE_FILE_MACHINE_AM33);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_AMD64", IMAGE_FILE_MACHINE_AMD64);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_ARM", IMAGE_FILE_MACHINE_ARM);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_ARM64", IMAGE_FILE_MACHINE_ARM64);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_ARMNT", IMAGE_FILE_MACHINE_ARMNT);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_EBC", IMAGE_FILE_MACHINE_EBC);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_I386", IMAGE_FILE_MACHINE_I386);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_IA64", IMAGE_FILE_MACHINE_IA64);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_M32R", IMAGE_FILE_MACHINE_M32R);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_MIPS16", IMAGE_FILE_MACHINE_MIPS16);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_MIPSFPU", IMAGE_FILE_MACHINE_MIPSFPU);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_MIPSFPU16", IMAGE_FILE_MACHINE_MIPSFPU16);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_POWERPC", IMAGE_FILE_MACHINE_POWERPC);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_POWERPCFP", IMAGE_FILE_MACHINE_POWERPCFP);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_R4000", IMAGE_FILE_MACHINE_R4000);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_RISCV32", IMAGE_FILE_MACHINE_RISCV32);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_RISCV64", IMAGE_FILE_MACHINE_RISCV64);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_RISCV128", IMAGE_FILE_MACHINE_RISCV128);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_SH3", IMAGE_FILE_MACHINE_SH3);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_SH3DSP", IMAGE_FILE_MACHINE_SH3DSP);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_SH4", IMAGE_FILE_MACHINE_SH4);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_SH5", IMAGE_FILE_MACHINE_SH5);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_THUMB", IMAGE_FILE_MACHINE_THUMB);
		coffHeaderMachineBuilder.AddMemberWithValue("IMAGE_FILE_MACHINE_WCEMIPSV2", IMAGE_FILE_MACHINE_WCEMIPSV2);

		Ref<Enumeration> coffHeaderMachineEnum = coffHeaderMachineBuilder.Finalize();
		Ref<Type> coffHeaderMachineEnumType = Type::EnumerationType(GetParentView()->GetDefaultArchitecture(), coffHeaderMachineEnum, 2, false);
		string coffHeaderMachineEnumName = "coff_machine";
		string coffHeaderMachineEnumId = Type::GenerateAutoTypeId("pe", coffHeaderMachineEnumName);
		QualifiedName coffHeaderMachineEnumTypeName = DefineType(coffHeaderMachineEnumId, coffHeaderMachineEnumName, coffHeaderMachineEnumType);

		EnumerationBuilder coffCharacteristicsBuilder;
		coffCharacteristicsBuilder.AddMemberWithValue("IMAGE_FILE_RELOCS_STRIPPED", IMAGE_FILE_RELOCS_STRIPPED);
		coffCharacteristicsBuilder.AddMemberWithValue("IMAGE_FILE_EXECUTABLE_IMAGE", IMAGE_FILE_EXECUTABLE_IMAGE);
		coffCharacteristicsBuilder.AddMemberWithValue("IMAGE_FILE_LINE_NUMS_STRIPPED", IMAGE_FILE_LINE_NUMS_STRIPPED);
		coffCharacteristicsBuilder.AddMemberWithValue("IMAGE_FILE_LOCAL_SYMS_STRIPPED", IMAGE_FILE_LOCAL_SYMS_STRIPPED);
		coffCharacteristicsBuilder.AddMemberWithValue("IMAGE_FILE_AGGRESIVE_WS_TRIM", IMAGE_FILE_AGGRESIVE_WS_TRIM);
		coffCharacteristicsBuilder.AddMemberWithValue("IMAGE_FILE_LARGE_ADDRESS_AWARE", IMAGE_FILE_LARGE_ADDRESS_AWARE);
		coffCharacteristicsBuilder.AddMemberWithValue("IMAGE_FILE_BYTES_REVERSED_LO", IMAGE_FILE_BYTES_REVERSED_LO);
		coffCharacteristicsBuilder.AddMemberWithValue("IMAGE_FILE_32BIT_MACHINE", IMAGE_FILE_32BIT_MACHINE);
		coffCharacteristicsBuilder.AddMemberWithValue("IMAGE_FILE_DEBUG_STRIPPED", IMAGE_FILE_DEBUG_STRIPPED);
		coffCharacteristicsBuilder.AddMemberWithValue("IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP", IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP);
		coffCharacteristicsBuilder.AddMemberWithValue("IMAGE_FILE_NET_RUN_FROM_SWAP", IMAGE_FILE_NET_RUN_FROM_SWAP);
		coffCharacteristicsBuilder.AddMemberWithValue("IMAGE_FILE_SYSTEM", IMAGE_FILE_SYSTEM);
		coffCharacteristicsBuilder.AddMemberWithValue("IMAGE_FILE_DLL", IMAGE_FILE_DLL);
		coffCharacteristicsBuilder.AddMemberWithValue("IMAGE_FILE_UP_SYSTEM_ONLY", IMAGE_FILE_UP_SYSTEM_ONLY);
		coffCharacteristicsBuilder.AddMemberWithValue("IMAGE_FILE_BYTES_REVERSED_HI", IMAGE_FILE_BYTES_REVERSED_HI);

		Ref<Enumeration> coffCharacteristicsEnum = coffCharacteristicsBuilder.Finalize();
		Ref<Type> coffCharacteristicsEnumType = Type::EnumerationType(GetParentView()->GetDefaultArchitecture(), coffCharacteristicsEnum, 2, false);
		string coffCharacteristicsEnumName = "coff_characteristics";
		string coffCharacteristicsEnumId = Type::GenerateAutoTypeId("pe", coffCharacteristicsEnumName);
		QualifiedName coffCharacteristicsEnumTypeName = DefineType(coffCharacteristicsEnumId, coffCharacteristicsEnumName, coffCharacteristicsEnumType);

		// TODO decorate members with comments once comments work with linear view
		StructureBuilder coffHeaderBuilder;
		coffHeaderBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 4), "magic");
		coffHeaderBuilder.AddMember(Type::NamedType(this, coffHeaderMachineEnumTypeName), "machine");
		coffHeaderBuilder.AddMember(Type::IntegerType(2, false), "numberOfSections");
		coffHeaderBuilder.AddMember(Type::IntegerType(4, false), "timeDateStamp");
		coffHeaderBuilder.AddMember(Type::IntegerType(4, false), "pointerToSymbolTable");
		coffHeaderBuilder.AddMember(Type::IntegerType(4, false), "numberOfSymbols");
		coffHeaderBuilder.AddMember(Type::IntegerType(2, false), "sizeOfOptionalHeader");
		coffHeaderBuilder.AddMember(Type::NamedType(this, coffCharacteristicsEnumTypeName), "characteristics");

		Ref<Structure> coffHeaderStruct = coffHeaderBuilder.Finalize();
		Ref<Type> coffHeaderType = Type::StructureType(coffHeaderStruct);
		QualifiedName coffHeaderName = string("COFF_Header");
		string coffHeaderTypeId = Type::GenerateAutoTypeId("pe", coffHeaderName);
		QualifiedName coffHeaderTypeName = DefineType(coffHeaderTypeId, coffHeaderName, coffHeaderType);
		DefineDataVariable(m_imageBase + peOfs, Type::NamedType(this, coffHeaderTypeName));
		DefineAutoSymbol(new Symbol(DataSymbol, "__coff_header", m_imageBase + peOfs, NoBinding));

		EnumerationBuilder peMagicBuilder;
		peMagicBuilder.AddMemberWithValue("PE_ROM_IMAGE", 0x107);
		peMagicBuilder.AddMemberWithValue("PE_32BIT", 0x10b);
		peMagicBuilder.AddMemberWithValue("PE_64BIT", 0x20b);

		Ref<Enumeration> peMagicEnum = peMagicBuilder.Finalize();
		Ref<Type> peMagicEnumType = Type::EnumerationType(GetParentView()->GetDefaultArchitecture(), peMagicEnum, 2, false);
		string peMagicEnumName = "pe_magic";
		string peMagicEnumId = Type::GenerateAutoTypeId("pe", peMagicEnumName);
		QualifiedName peMagicEnumTypeName = DefineType(peMagicEnumId, peMagicEnumName, peMagicEnumType);

		EnumerationBuilder peSubsystemBuilder;
		peSubsystemBuilder.AddMemberWithValue("IMAGE_SUBSYSTEM_UNKNOWN", IMAGE_SUBSYSTEM_UNKNOWN);
		peSubsystemBuilder.AddMemberWithValue("IMAGE_SUBSYSTEM_NATIVE", IMAGE_SUBSYSTEM_NATIVE);
		peSubsystemBuilder.AddMemberWithValue("IMAGE_SUBSYSTEM_WINDOWS_GUI", IMAGE_SUBSYSTEM_WINDOWS_GUI);
		peSubsystemBuilder.AddMemberWithValue("IMAGE_SUBSYSTEM_WINDOWS_CUI", IMAGE_SUBSYSTEM_WINDOWS_CUI);
		peSubsystemBuilder.AddMemberWithValue("IMAGE_SUBSYSTEM_OS2_CUI", IMAGE_SUBSYSTEM_OS2_CUI);
		peSubsystemBuilder.AddMemberWithValue("IMAGE_SUBSYSTEM_POSIX_CUI", IMAGE_SUBSYSTEM_POSIX_CUI);
		peSubsystemBuilder.AddMemberWithValue("IMAGE_SUBSYSTEM_NATIVE_WINDOWS", IMAGE_SUBSYSTEM_NATIVE_WINDOWS);
		peSubsystemBuilder.AddMemberWithValue("IMAGE_SUBSYSTEM_WINDOWS_CE_GUI", IMAGE_SUBSYSTEM_WINDOWS_CE_GUI);
		peSubsystemBuilder.AddMemberWithValue("IMAGE_SUBSYSTEM_EFI_APPLICATION", IMAGE_SUBSYSTEM_EFI_APPLICATION);
		peSubsystemBuilder.AddMemberWithValue("IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER);
		peSubsystemBuilder.AddMemberWithValue("IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER", IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER);
		peSubsystemBuilder.AddMemberWithValue("IMAGE_SUBSYSTEM_EFI_ROM", IMAGE_SUBSYSTEM_EFI_ROM);
		peSubsystemBuilder.AddMemberWithValue("IMAGE_SUBSYSTEM_XBOX", IMAGE_SUBSYSTEM_XBOX);
		peSubsystemBuilder.AddMemberWithValue("IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION", IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION);

		Ref<Enumeration> peSubsystemEnum = peSubsystemBuilder.Finalize();
		Ref<Type> peSubsystemEnumType = Type::EnumerationType(GetParentView()->GetDefaultArchitecture(), peSubsystemEnum, 2, false);
		string peSubsystemEnumName = "pe_subsystem";
		string peSubsystemEnumId = Type::GenerateAutoTypeId("pe", peSubsystemEnumName);
		QualifiedName peSubsystemEnumTypeName = DefineType(peSubsystemEnumId, peSubsystemEnumName, peSubsystemEnumType);

		EnumerationBuilder dllCharacteristicsBuilder;
		dllCharacteristicsBuilder.AddMemberWithValue("IMAGE_DLLCHARACTERISTICS_0001", IMAGE_DLLCHARACTERISTICS_0001);
		dllCharacteristicsBuilder.AddMemberWithValue("IMAGE_DLLCHARACTERISTICS_0002", IMAGE_DLLCHARACTERISTICS_0002);
		dllCharacteristicsBuilder.AddMemberWithValue("IMAGE_DLLCHARACTERISTICS_0004", IMAGE_DLLCHARACTERISTICS_0004);
		dllCharacteristicsBuilder.AddMemberWithValue("IMAGE_DLLCHARACTERISTICS_0008", IMAGE_DLLCHARACTERISTICS_0008);
		dllCharacteristicsBuilder.AddMemberWithValue("IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA", IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA);
		dllCharacteristicsBuilder.AddMemberWithValue("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
		dllCharacteristicsBuilder.AddMemberWithValue("IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY);
		dllCharacteristicsBuilder.AddMemberWithValue("IMAGE_DLLCHARACTERISTICS_NX_COMPAT", IMAGE_DLLCHARACTERISTICS_NX_COMPAT);
		dllCharacteristicsBuilder.AddMemberWithValue("IMAGE_DLLCHARACTERISTICS_NO_ISOLATION", IMAGE_DLLCHARACTERISTICS_NO_ISOLATION);
		dllCharacteristicsBuilder.AddMemberWithValue("IMAGE_DLLCHARACTERISTICS_NO_SEH", IMAGE_DLLCHARACTERISTICS_NO_SEH);
		dllCharacteristicsBuilder.AddMemberWithValue("IMAGE_DLLCHARACTERISTICS_NO_BIND", IMAGE_DLLCHARACTERISTICS_NO_BIND);
		dllCharacteristicsBuilder.AddMemberWithValue("IMAGE_DLLCHARACTERISTICS_APPCONTAINER", IMAGE_DLLCHARACTERISTICS_APPCONTAINER);
		dllCharacteristicsBuilder.AddMemberWithValue("IMAGE_DLLCHARACTERISTICS_WDM_DRIVER", IMAGE_DLLCHARACTERISTICS_WDM_DRIVER);
		dllCharacteristicsBuilder.AddMemberWithValue("IMAGE_DLLCHARACTERISTICS_GUARD_CF", IMAGE_DLLCHARACTERISTICS_GUARD_CF);
		dllCharacteristicsBuilder.AddMemberWithValue("IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE", IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE);

		Ref<Enumeration> dllCharacteristicsEnum = dllCharacteristicsBuilder.Finalize();
		Ref<Type> dllCharacteristicsEnumType = Type::EnumerationType(GetParentView()->GetDefaultArchitecture(), dllCharacteristicsEnum, 2, false);
		string dllCharacteristicsEnumName = "pe_dll_characteristics";
		string dllCharacteristicsEnumId = Type::GenerateAutoTypeId("pe", dllCharacteristicsEnumName);
		QualifiedName dllCharacteristicsEnumTypeName = DefineType(dllCharacteristicsEnumId, dllCharacteristicsEnumName, dllCharacteristicsEnumType);

		// Create PE Optional Header Type
		StructureBuilder peOptionalHeaderBuilder;
		peOptionalHeaderBuilder.AddMember(Type::NamedType(this, peMagicEnumTypeName), "magic");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(1, false), "majorLinkerVersion");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(1, false), "minorLinkerVersion");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(4, false), "sizeOfCode");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(4, false), "sizeOfInitializedData");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(4, false), "sizeOfUninitializedData");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(4, false), "addressOfEntryPoint");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(4, false), "baseOfCode");
		if (!m_is64)
			peOptionalHeaderBuilder.AddMember(Type::IntegerType(4, false), "baseOfData");
		size_t opFieldSize = m_is64 ? 8 : 4;
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(opFieldSize, false), "imageBase");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(4, false), "sectionAlignment");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(4, false), "fileAlignment");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(2, false), "majorOperatingSystemVersion");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(2, false), "minorOperatingSystemVersion");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(2, false), "majorImageVersion");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(2, false), "minorImageVersion");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(2, false), "majorSubsystemVersion");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(2, false), "minorSubsystemVersion");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(4, false), "win32VersionValue");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(4, false), "sizeOfImage");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(4, false), "sizeOfHeaders");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(4, false), "checkSum");
		peOptionalHeaderBuilder.AddMember(Type::NamedType(this, peSubsystemEnumTypeName), "subsystem");
		peOptionalHeaderBuilder.AddMember(Type::NamedType(this, dllCharacteristicsEnumTypeName), "dllCharacteristics");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(opFieldSize, false), "sizeOfStackReserve");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(opFieldSize, false), "sizeOfStackCommit");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(opFieldSize, false), "sizeOfHeapReserve");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(opFieldSize, false), "sizeOfHeapCommit");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(4, false), "loaderFlags");
		peOptionalHeaderBuilder.AddMember(Type::IntegerType(4, false), "numberOfRvaAndSizes");

		if (opt.dataDirCount)
		{
			StructureBuilder dataDirEntryBuilder;
			dataDirEntryBuilder.AddMember(Type::IntegerType(4, false), "virtualAddress");
			dataDirEntryBuilder.AddMember(Type::IntegerType(4, false), "size");

			Ref<Structure> dataDirEntryStruct = dataDirEntryBuilder.Finalize();
			Ref<Type> dataDirEntryType = Type::StructureType(dataDirEntryStruct);
			QualifiedName dataDirName = string("PE_Data_Directory_Entry");
			string dataDirTypeId = Type::GenerateAutoTypeId("pe", dataDirName);
			QualifiedName dataDirTypeName = DefineType(dataDirTypeId, dataDirName, dataDirEntryType);
			size_t dataDirNameCount = std::extent<decltype(imageDirName)>::value;
			for (size_t i = 0; i < opt.dataDirCount; i++)
			{
				string dirName = (i < std::extent<decltype(imageDirName)>::value) ? imageDirName[i] : imageDirName[dataDirNameCount - 1];
				peOptionalHeaderBuilder.AddMember(Type::NamedType(this, dataDirTypeName), dirName + "Entry");
			}

		}

		string peHdrPrefix = m_is64 ? "pe64" : "pe32";
		Ref<Structure> peOptionalHeaderStruct = peOptionalHeaderBuilder.Finalize();
		Ref<Type> peOptionalHeaderType = Type::StructureType(peOptionalHeaderStruct);
		QualifiedName peOptionalHeaderName = m_is64 ? string("PE64_Optional_Header") : string("PE32_Optional_Header");
		string peOptionalHeaderTypeId = Type::GenerateAutoTypeId("pe", peOptionalHeaderName);
		QualifiedName peOptionalHeaderTypeName = DefineType(peOptionalHeaderTypeId, peOptionalHeaderName, peOptionalHeaderType);
		DefineDataVariable(m_imageBase + optionalHeaderOffset, Type::NamedType(this, peOptionalHeaderTypeName));
		DefineAutoSymbol(new Symbol(DataSymbol, "__" + peHdrPrefix + "_optional_header", m_imageBase + optionalHeaderOffset, NoBinding));

		EnumerationBuilder peSectionFlagsBuilder;
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_RESERVED_0001", IMAGE_SCN_RESERVED_0001);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_RESERVED_0002", IMAGE_SCN_RESERVED_0002);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_RESERVED_0004", IMAGE_SCN_RESERVED_0004);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_TYPE_NO_PAD", IMAGE_SCN_TYPE_NO_PAD);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_RESERVED_0010", IMAGE_SCN_RESERVED_0010);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_CNT_CODE", IMAGE_SCN_CNT_CODE);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_CNT_INITIALIZED_DATA", IMAGE_SCN_CNT_INITIALIZED_DATA);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_CNT_UNINITIALIZED_DATA", IMAGE_SCN_CNT_UNINITIALIZED_DATA);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_LNK_OTHER", IMAGE_SCN_LNK_OTHER);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_LNK_INFO", IMAGE_SCN_LNK_INFO);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_RESERVED_0400", IMAGE_SCN_RESERVED_0400);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_LNK_REMOVE", IMAGE_SCN_LNK_REMOVE);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_LNK_COMDAT", IMAGE_SCN_LNK_COMDAT);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_GPREL", IMAGE_SCN_GPREL);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_MEM_PURGEABLE", IMAGE_SCN_MEM_PURGEABLE);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_MEM_16BIT", IMAGE_SCN_MEM_16BIT);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_MEM_LOCKED", IMAGE_SCN_MEM_LOCKED);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_MEM_PRELOAD", IMAGE_SCN_MEM_PRELOAD);
		// TODO fix the bug that causes flags to not be displayed when these are added to the enumeration
		// peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_ALIGN_1BYTES", IMAGE_SCN_ALIGN_1BYTES);
		// peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_ALIGN_2BYTES", IMAGE_SCN_ALIGN_2BYTES);
		// peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_ALIGN_4BYTES", IMAGE_SCN_ALIGN_4BYTES);
		// peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_ALIGN_8BYTES", IMAGE_SCN_ALIGN_8BYTES);
		// peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_ALIGN_16BYTES", IMAGE_SCN_ALIGN_16BYTES);
		// peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_ALIGN_32BYTES", IMAGE_SCN_ALIGN_32BYTES);
		// peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_ALIGN_64BYTES", IMAGE_SCN_ALIGN_64BYTES);
		// peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_ALIGN_128BYTES", IMAGE_SCN_ALIGN_128BYTES);
		// peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_ALIGN_256BYTES", IMAGE_SCN_ALIGN_256BYTES);
		// peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_ALIGN_512BYTES", IMAGE_SCN_ALIGN_512BYTES);
		// peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_ALIGN_1024BYTES", IMAGE_SCN_ALIGN_1024BYTES);
		// peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_ALIGN_2048BYTES", IMAGE_SCN_ALIGN_2048BYTES);
		// peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_ALIGN_4096BYTES", IMAGE_SCN_ALIGN_4096BYTES);
		// peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_ALIGN_8192BYTES", IMAGE_SCN_ALIGN_8192BYTES);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_LNK_NRELOC_OVFL", IMAGE_SCN_LNK_NRELOC_OVFL);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_MEM_DISCARDABLE", IMAGE_SCN_MEM_DISCARDABLE);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_MEM_NOT_CACHED", IMAGE_SCN_MEM_NOT_CACHED);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_MEM_NOT_PAGED", IMAGE_SCN_MEM_NOT_PAGED);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_MEM_SHARED", IMAGE_SCN_MEM_SHARED);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_MEM_EXECUTE", IMAGE_SCN_MEM_EXECUTE);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_MEM_READ", IMAGE_SCN_MEM_READ);
		peSectionFlagsBuilder.AddMemberWithValue("IMAGE_SCN_MEM_WRITE", IMAGE_SCN_MEM_WRITE);

		Ref<Enumeration> peSectionFlagsEnum = peSectionFlagsBuilder.Finalize();
		Ref<Type> peSectionFlagsEnumType = Type::EnumerationType(GetParentView()->GetDefaultArchitecture(), peSectionFlagsEnum, 4, false);
		string peSectionFlagsEnumName = "pe_section_flags";
		string peSectionFlagsEnumId = Type::GenerateAutoTypeId("pe", peSectionFlagsEnumName);
		QualifiedName peSectionFlagsEnumTypeName = DefineType(peSectionFlagsEnumId, peSectionFlagsEnumName, peSectionFlagsEnumType);

		if (header.sectionCount)
		{
			StructureBuilder sectionHeaderBuilder;
			sectionHeaderBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 8), "name");
			sectionHeaderBuilder.AddMember(Type::IntegerType(4, false), "virtualSize");
			sectionHeaderBuilder.AddMember(Type::IntegerType(4, false), "virtualAddress");
			sectionHeaderBuilder.AddMember(Type::IntegerType(4, false), "sizeOfRawData");
			sectionHeaderBuilder.AddMember(Type::IntegerType(4, false), "pointerToRawData");
			sectionHeaderBuilder.AddMember(Type::IntegerType(4, false), "pointerToRelocations");
			sectionHeaderBuilder.AddMember(Type::IntegerType(4, false), "pointerToLineNumbers");
			sectionHeaderBuilder.AddMember(Type::IntegerType(2, false), "numberOfRelocations");
			sectionHeaderBuilder.AddMember(Type::IntegerType(2, false), "numberOfLineNumbers");
			sectionHeaderBuilder.AddMember(Type::NamedType(this, peSectionFlagsEnumTypeName), "characteristics");

			Ref<Structure> sectionHeaderStruct = sectionHeaderBuilder.Finalize();
			Ref<Type> sectionHeaderStructType = Type::StructureType(sectionHeaderStruct);
			QualifiedName sectionHeaderName = string("Section_Header");
			string sectionHeaderTypeId = Type::GenerateAutoTypeId("pe", sectionHeaderName);
			QualifiedName sectionHeaderTypeName = DefineType(sectionHeaderTypeId, sectionHeaderName, sectionHeaderStructType);

			size_t sectionHeaderOffset = optionalHeaderOffset + header.optionalHeaderSize;
			DefineDataVariable(m_imageBase + sectionHeaderOffset, Type::ArrayType(Type::NamedType(this, sectionHeaderTypeName), header.sectionCount));
			DefineAutoSymbol(new Symbol(DataSymbol, "__section_headers", m_imageBase + sectionHeaderOffset, NoBinding));
		}
	}
	catch (std::exception& e)
	{
		m_logger->LogError("Failed to parse PE headers: %s\n", e.what());
		return false;
	}

	vector<pair<BNRelocationInfo, string>> relocs;
	BeginBulkModifySymbols();
	m_symbolQueue = new SymbolQueue();
	m_symExternMappingMetadata = new Metadata(KeyValueDataType);

	try
	{
		// Process COFF symbol table
		if (header.coffSymbolCount)
		{
			BinaryReader stringReader(GetParentView(), LittleEndian);
			uint64_t stringTableBase = header.coffSymbolTable + (header.coffSymbolCount * 18);
			stringReader.Seek(stringTableBase);
			if ((stringTableBase + stringReader.Read32()) > GetParentView()->GetEnd())
			{
				throw PEFormatException("invalid COFF string table size");
			}

			for (size_t i = 0; i < header.coffSymbolCount; i++)
			{
				reader.Seek(header.coffSymbolTable + (i * 18));
				uint32_t e_zeroes = reader.Read32();
				uint32_t e_offset = reader.Read32();
				uint32_t e_value = reader.Read32();
				uint16_t e_scnum = reader.Read16();
				uint16_t e_type = reader.Read16();
				uint8_t e_sclass = reader.Read8();
				uint8_t e_numaux = reader.Read8();

				uint64_t virtualAddress = 0;
				switch (e_scnum)
				{
					case IMAGE_SYM_UNDEFINED:
					case (uint16_t)IMAGE_SYM_ABSOLUTE:
					case (uint16_t)IMAGE_SYM_DEBUG:
						break;
					default:
						if (size_t(e_scnum - 1) < m_sections.size())
							virtualAddress = m_sections[size_t(e_scnum - 1)].virtualAddress + e_value;
						break;
				}

				// read symbol name
				string symbolName;
				if (virtualAddress)
				{
					if (e_zeroes)
					{
						stringReader.Seek(header.coffSymbolTable + (i * 18));
						symbolName = stringReader.ReadCString(8);
					}
					else
					{
						stringReader.Seek(stringTableBase + e_offset);
						symbolName = stringReader.ReadCString();
					}
				}

				BNSymbolBinding binding;
				switch (e_sclass)
				{
					case IMAGE_SYM_CLASS_EXTERNAL:
					case IMAGE_SYM_CLASS_STATIC:
						binding = LocalBinding;
						break;
					default:
						binding = NoBinding;
						break;
				}

				// if (virtualAddress)
				// 	m_logger->LogError("RawOffset:0x%x StorageClass:%u Type:%x NumAux:%x VA: 0x%x section:%x %s",
				// header.coffSymbolTable + (i * 18), e_sclass, e_type, e_numaux, virtualAddress + m_imageBase, e_scnum,
				// symbolName.c_str()); else 	m_logger->LogError("RawOffset:0x%x StorageClass:%u Type:%x NumAux:%x VA: 0x%x
				// section:%x value: %x", header.coffSymbolTable + (i * 18), e_sclass, e_type, e_numaux, virtualAddress
				// + m_imageBase, e_scnum, e_value);

				uint8_t baseType = (e_type >> 4) & 0x3;
				switch (baseType)
				{
					case IMAGE_SYM_DTYPE_NULL: // no derived type
					{
						if (virtualAddress)
							AddPESymbol(DataSymbol, "", symbolName, virtualAddress, binding);
						break;
					}
					case IMAGE_SYM_DTYPE_POINTER: // pointer to base type
					{
						break;
					}
					case IMAGE_SYM_DTYPE_FUNCTION: // function that returns base type
					{
						//LogError("%x StorageClass:%u Type:%x NumAux:%x COFF_DT_FCN at %x section:%x %s ", header.coffSymbolTable + (i * 18), e_sclass, e_type, e_numaux, virtualAddress + m_imageBase, e_scnum, symbolName.c_str());
						if (virtualAddress)
							AddPESymbol(FunctionSymbol, "", symbolName, virtualAddress, binding);
						break;
					}
					case IMAGE_SYM_DTYPE_ARRAY: // array of base type
					{
						break;
					}
					default:
						break;
				}

				// TODO handle auxiliary entries
				i += e_numaux;
			}
		}
	}
	catch (std::exception& e)
	{
		m_logger->LogError("Failed to parse COFF symbol table: %s\n", e.what());
	}

	try
	{
		PEDataDirectory dir;
		// Read import directory
		if (m_dataDirs.size() > IMAGE_DIRECTORY_ENTRY_IMPORT)
			dir = m_dataDirs[IMAGE_DIRECTORY_ENTRY_IMPORT];
		else
			dir.virtualAddress = 0;

		if (dir.virtualAddress > 0)
		{
			size_t numImportEntries = 0;
			vector<Ref<Metadata>> libraries;
			vector<Ref<Metadata>> libraryFound;
			while (true)
			{
				// Read in next directory entry
				reader.Seek(RVAToFileOffset(dir.virtualAddress + (numImportEntries * 20)));
				PEImportDirectoryEntry importDirEntry;
				importDirEntry.lookup = reader.Read32();
				importDirEntry.timestamp = reader.Read32();
				importDirEntry.forwardChain = reader.Read32();
				importDirEntry.nameAddress = reader.Read32();
				importDirEntry.iat = reader.Read32();

				// Windows PE loader ignores the dir.size; instead, it looks for the first
				// Import_Directory_Table that has a null nameAddress to stop the iteration
				if (importDirEntry.nameAddress == 0)
				{
					if (numImportEntries + 1 != dir.size / 20)
						m_logger->LogWarn(
							"The number of Import_Directory_Table reported by the Data Directories is different from "
							"its correct amount. "
							"There are actually %d Import_Directory_Table in the file, but SizeOfImportTable reports "
							"%d. "
							"The PE parsing continues with the actual number of Import_Directory_Table",
							numImportEntries + 1, dir.size / 20);
					break;
				}

				// Read name of imported DLL, and trim extension for creating symbol name
				importDirEntry.name = ReadString(importDirEntry.nameAddress);
				Ref<ExternalLibrary> externLib = GetExternalLibrary(importDirEntry.name);
				if (!externLib)
				{
					externLib = AddExternalLibrary(importDirEntry.name, {}, true);
				}
				libraries.push_back(new Metadata(string(importDirEntry.name)));
				string lowerName = importDirEntry.name;
				std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
						[](unsigned char c){ return std::tolower(c); });

				vector<Ref<TypeLibrary>> typeLibs = platform->GetTypeLibrariesByName(lowerName);
				for (const auto& typeLib : typeLibs)
				{
					// Check if the type library is already added
					if (GetTypeLibrary(typeLib->GetName()))
						continue;
					AddTypeLibrary(typeLib);

					m_logger->LogDebug("pe: adding type library for '%s': %s (%s)", lowerName.c_str(),
						typeLib->GetName().c_str(), typeLib->GetGuid().c_str());
				}

				Ref<Metadata> ordinals;
				if (typeLibs.size())
				{
					for (const auto& typeLib : typeLibs)
					{
						char ordinal_subsystem[64];
						snprintf(ordinal_subsystem, sizeof(ordinal_subsystem), "ordinals_%hu_%hu", opt.majorOSVersion, opt.minorOSVersion);
						ordinals = typeLib->QueryMetadata("ordinals");
						libraryFound.push_back(new Metadata(string(typeLib->GetName())));
						if (ordinals && ordinals->IsString())
							ordinals = typeLib->QueryMetadata(ordinals->GetString());

						if (ordinals && !ordinals->IsKeyValueStore())
							ordinals = nullptr;
					}
				}
				else
					libraryFound.push_back(new Metadata(string("")));


				size_t dotPos = importDirEntry.name.rfind('.');
				string dllName;
				if (dotPos == string::npos)
					dllName = importDirEntry.name;
				else
					dllName = importDirEntry.name.substr(0, dotPos);

				// Create Import DLL Name Type
				DefineDataVariable(m_imageBase + importDirEntry.nameAddress, Type::ArrayType(Type::IntegerType(1, true), importDirEntry.name.size() + 1));
				DefineAutoSymbol(new Symbol(DataSymbol, "__import_dll_name(" + dllName + ")", m_imageBase + importDirEntry.nameAddress, NoBinding));

				// Parse list of imported functions
				uint32_t entryOffset = importDirEntry.lookup;
				uint32_t iatOffset = importDirEntry.iat;

				if ((entryOffset == 0) && (iatOffset != 0))
					entryOffset = iatOffset;

				// TODO: entryOffset and iatOffset point to two copies of the same data
				// We should make this second unused data a structure containing this information information
				// and default it to collapsed...IDA Just doesn't show anything at all
				m_logger->LogDebug("Name: %s\n", dllName.c_str());
				while (true)
				{
					uint64_t entry;
					bool isOrdinal;
					if (m_is64)
					{
						entry = Read64(entryOffset);
						isOrdinal = (entry & 0x8000000000000000LL) != 0;
						entry &= 0x7fffffffffffffffLL;
						DefineDataVariable(m_imageBase + entryOffset, Type::IntegerType(8, false));
					}
					else
					{
						entry = Read32(entryOffset);
						isOrdinal = (entry & 0x80000000) != 0;
						entry &= 0x7fffffff;
						DefineDataVariable(m_imageBase + entryOffset, Type::IntegerType(4, false));
					}
					m_logger->LogDebug("Entry 0x%llx isOrdinal: %s\n", entry, isOrdinal ? "True" : "False");

					if ((!isOrdinal) && (entry == 0))
						break;

					string func;
					uint16_t ordinal;
					if (isOrdinal)
					{
						ordinal = (uint16_t)entry;
						string ordString = to_string(ordinal);
						Ref<Metadata> ordInfo = nullptr;

						if (ordinals)
							ordInfo = ordinals->Get(ordString);

						if (ordInfo && ordInfo->IsString())
							func = ordInfo->GetString();
						else
							func = "Ordinal_" + dllName + "_" + to_string((int)entry);
					}
					else
					{
						ordinal = Read16(entry);
						func = ReadString(entry + 2);
						DefineDataVariable(m_imageBase + entry, Type::IntegerType(2, false));
						DefineAutoSymbol(new Symbol(DataSymbol, "__export_name_ptr_table_" + to_string(numImportEntries) + "(" + dllName + ":" + func + ")", m_imageBase + entry, NoBinding));
						DefineDataVariable(m_imageBase + entry + 2, Type::ArrayType(Type::IntegerType(1, true), func.size() + 1));
						DefineAutoSymbol(new Symbol(DataSymbol, "__import_name_" + to_string(numImportEntries) + "(" + dllName + ":" + func + ")", m_imageBase + entry + 2, NoBinding));
						DefineAutoSymbol(new Symbol(DataSymbol, "__import_lookup_table_" + to_string(numImportEntries) + "(" + dllName + ":" + func + ")", m_imageBase + entryOffset, NoBinding));
					}
					m_logger->LogDebug("FuncString: %s\n", func.c_str());
					AddPESymbol(ImportAddressSymbol, dllName, func, iatOffset, NoBinding, ordinal, typeLibs);
					AddPESymbol(ExternalSymbol, dllName, func, 0, NoBinding, ordinal, typeLibs);

					if (externLib)
						m_symExternMappingMetadata->SetValueForKey(func, new Metadata(externLib->GetName()));

					BNRelocationInfo reloc;
					memset(&reloc, 0, sizeof(reloc));
					reloc.nativeType = -1;
					reloc.address = m_imageBase + iatOffset;
					reloc.size = m_is64 ? 8 : 4;
					reloc.pcRelative = false;
					reloc.base = m_imageBase - m_peImageBase;
					reloc.external = true;
					relocs.push_back({reloc, func});
					entryOffset += m_is64 ? 8 : 4;
					iatOffset += m_is64 ? 8 : 4;
				}

				numImportEntries++;
			}

			StoreMetadata("Libraries", new Metadata(libraries), true);
			StoreMetadata("LibraryFound", new Metadata(libraryFound), true);
			if (numImportEntries)
			{
				// Create Import Directory Table Type
				StructureBuilder importDirBuilder;
				importDirBuilder.AddMember(Type::IntegerType(4, false), "importLookupTableRva");
				importDirBuilder.AddMember(Type::IntegerType(4, false), "timeDateStamp");
				importDirBuilder.AddMember(Type::IntegerType(4, false), "forwarderChain");
				importDirBuilder.AddMember(Type::IntegerType(4, false), "nameRva");
				importDirBuilder.AddMember(Type::IntegerType(4, false), "importAddressTableRva");

				Ref<Structure> importDirStruct = importDirBuilder.Finalize();
				Ref<Type> importDirType = Type::StructureType(importDirStruct);
				QualifiedName importDirName = string("Import_Directory_Table");
				string importDirTypeId = Type::GenerateAutoTypeId("pe", importDirName);
				QualifiedName importDirTypeName = DefineType(importDirTypeId, importDirName, importDirType);
				DefineDataVariable(m_imageBase + m_dataDirs[IMAGE_DIRECTORY_ENTRY_IMPORT].virtualAddress, Type::ArrayType(Type::NamedType(this, importDirTypeName), numImportEntries + 1));
				DefineAutoSymbol(new Symbol(DataSymbol, "__import_directory_entries", m_imageBase + m_dataDirs[IMAGE_DIRECTORY_ENTRY_IMPORT].virtualAddress, NoBinding));
			}
		}
	}
	catch (std::exception& e)
	{
		m_logger->LogWarn("Failed to parse import directory: %s\n", e.what());
	}

	try
	{
		if ((m_dataDirs.size() > IMAGE_DIRECTORY_ENTRY_EXCEPTION) && m_dataDirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].size)
		{
			// Create Exception Directory Table Entry Type
			size_t entrySize;
			size_t numExceptionEntries;
			StructureBuilder exceptionEntryBuilder;
			switch (header.machine)
			{
				case IMAGE_FILE_MACHINE_AMD64:
				case IMAGE_FILE_MACHINE_IA64:
				{
					entrySize = 12;
					exceptionEntryBuilder.AddMember(Type::IntegerType(4, false), "beginAddress");
					exceptionEntryBuilder.AddMember(Type::IntegerType(4, false), "endAddress");
					exceptionEntryBuilder.AddMember(Type::IntegerType(4, false), "unwindInformation");
					break;
				}
				case IMAGE_FILE_MACHINE_MIPSFPU:
				case IMAGE_FILE_MACHINE_R4000:
				case IMAGE_FILE_MACHINE_WCEMIPSV2:
				{
					entrySize = 20;
					exceptionEntryBuilder.AddMember(Type::IntegerType(4, false), "beginAddress");
					exceptionEntryBuilder.AddMember(Type::IntegerType(4, false), "endAddress");
					exceptionEntryBuilder.AddMember(Type::IntegerType(4, false), "exceptionHandler");
					exceptionEntryBuilder.AddMember(Type::IntegerType(4, false), "handlerData");
					exceptionEntryBuilder.AddMember(Type::IntegerType(4, false), "prologEndAddress");
					break;
				}
				default:
				{
					entrySize = 8;
					exceptionEntryBuilder.AddMember(Type::IntegerType(4, false), "beginAddress");
					exceptionEntryBuilder.AddMember(Type::IntegerType(4, false), "otherInformation");
					break;
				}
			}

			if (m_dataDirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].size % entrySize)
				throw PEFormatException("invalid table size");
			numExceptionEntries = m_dataDirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].size / entrySize;

			// This DataVariable can end up creating a large array and rendering this in LinearView currently has performance implications
			// So instead we just create separate structures not in an array
			Ref<Structure> exceptionEntryStruct = exceptionEntryBuilder.Finalize();
			Ref<Type> exceptionEntryType = Type::StructureType(exceptionEntryStruct);
			QualifiedName exceptionEntryName = string("Exception_Directory_Entry");
			string exceptionEntryTypeId = Type::GenerateAutoTypeId("pe", exceptionEntryName);
			QualifiedName exceptionEntryTypeName = DefineType(exceptionEntryTypeId, exceptionEntryName, exceptionEntryType);
			for (size_t i = 0; i < numExceptionEntries; i++)
			{
				DefineDataVariable(m_imageBase + m_dataDirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].virtualAddress + (entrySize * i), Type::NamedType(this, exceptionEntryTypeName));
				DefineAutoSymbol(new Symbol(DataSymbol, "__exception_directory_entries(" + string(std::to_string(i)) + ")", m_imageBase + m_dataDirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].virtualAddress + (entrySize * i), NoBinding));
			}

			// parse exception table and add functions
			bool processExceptionTable = true;
			if (settings && settings->Contains("loader.pe.processExceptionTable"))
				processExceptionTable = settings->Get<bool>("loader.pe.processExceptionTable", this);
			if (processExceptionTable)
			{
				StructureBuilder unwindInfoStructBuilder;
				unwindInfoStructBuilder.AddMember(Type::IntegerType(1, false), "VersionAndFlag");
				unwindInfoStructBuilder.AddMember(Type::IntegerType(1, false), "SizeOfProlog");
				unwindInfoStructBuilder.AddMember(Type::IntegerType(1, false), "CountOfUnwindCodes");
				unwindInfoStructBuilder.AddMember(Type::IntegerType(1, false), "FrameRegisterAndFrameRegisterOffset");

				Ref<Structure> unwindInfoStruct = unwindInfoStructBuilder.Finalize();
				Ref<Type> unwindInfoStructType = Type::StructureType(unwindInfoStruct);
				QualifiedName unwindInfoName = string("UNWIND_INFO");
				string unwindInfoTypeId = Type::GenerateAutoTypeId("pe", unwindInfoName);
				QualifiedName unwindInfo = DefineType(unwindInfoTypeId, unwindInfoName, unwindInfoStructType);

				BinaryReader unwindReader(GetParentView(), LittleEndian);
				for (size_t i = 0; i < numExceptionEntries; i++)
				{
					reader.Seek(RVAToFileOffset(m_dataDirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].virtualAddress + (i * entrySize)));
					uint32_t beginAddress = reader.Read32();
					switch (header.machine)
					{
						case IMAGE_FILE_MACHINE_AMD64:
						case IMAGE_FILE_MACHINE_IA64:
						{
							reader.SeekRelative(4);  // EndAddress
							uint32_t unwindRva = reader.Read32();
							DefineDataVariable(m_imageBase + unwindRva, Type::NamedType(this, unwindInfo));
							unwindReader.Seek(RVAToFileOffset(unwindRva));
							uint32_t unwindInformation = unwindReader.Read32();
							uint8_t unwindCodeCount = (unwindInformation >> 16) & 0xff;
							if (unwindCodeCount > 0)
								DefineDataVariable(m_imageBase + unwindRva + 4, Type::ArrayType(Type::IntegerType(2, false), unwindCodeCount));

							auto current = m_imageBase + unwindRva + 4 + (unwindCodeCount * 2);
							if (current % 4 != 0)
								current += 4 - (current % 4); // Align to DWORD

							if (unwindInformation & (UNW_FLAG_CHAININFO << 3))
							{
								DefineDataVariable(current, Type::NamedType(this, exceptionEntryTypeName));
								continue;
							}
							else if ((unwindInformation & (UNW_FLAG_UHANDLER << 3)) || (unwindInformation & (UNW_FLAG_EHANDLER << 3)))
							{
								DefineDataVariable(current, Type::IntegerType(4, false));
								// unwindReader.Seek(RVAToFileOffset(unwindRva + 8 + (unwindCodeCount * 2)));
								// uint32_t count = unwindReader.Read32();
								// DefineDataVariable(current + 4, Type::ArrayType(Type::IntegerType(4, false), 3));
							}
							break;
						}
						default:
							break;
					}
					uint64_t exceptionEntry = m_imageBase + beginAddress;
					Ref<Platform> targetPlatform = platform->GetAssociatedPlatformByAddress(exceptionEntry);
					AddFunctionForAnalysis(targetPlatform, exceptionEntry);
				}
			}
		}
	}
	catch (std::exception& e)
	{
		m_logger->LogWarn("Failed to parse exception directory: %s\n", e.what());
	}

	try
	{
		if (m_dataDirs.size() > IMAGE_DIRECTORY_ENTRY_DEBUG)
		{
			PEDataDirectory dir = m_dataDirs[IMAGE_DIRECTORY_ENTRY_DEBUG];
			if (dir.size >= sizeof(DebugDirectory))
			{

				m_logger->LogDebug("Parsing IMAGE_DIRECTORY_ENTRY_DEBUG: %08x", dir.size);
				for (uint32_t i = 0; i < dir.size / sizeof(DebugDirectory); i++)
				{
					reader.Seek(RVAToFileOffset(dir.virtualAddress + i * sizeof(DebugDirectory)));
					DebugDirectory debugDir;
					reader.Read(&debugDir, sizeof(DebugDirectory));

					m_logger->LogDebug(
						"DebugDirectory:\n"
						"\tcharacteristics:  %08x\n"
						"\ttimeDateStamp:    %08x\n"
						"\tmajorVersion:     %08x\n"
						"\tminorVersion:     %08x\n"
						"\ttype:             %08x\n"
						"\tsizeOfData:       %08x\n"
						"\taddressOfRawData: %08x\n"
						"\tpointerToRawData: %08x\n",
						debugDir.characteristics,
						debugDir.timeDateStamp,
						debugDir.majorVersion,
						debugDir.minorVersion,
						debugDir.type,
						debugDir.sizeOfData,
						RVAToFileOffset(debugDir.addressOfRawData, false),
						debugDir.pointerToRawData
					);

					if (!debugDir.addressOfRawData)
						continue;

					if (debugDir.type == IMAGE_DEBUG_TYPE_CODEVIEW)  // PDB Information
					{
						auto type = TypeBuilder::IntegerType(4, false);
						type.SetIntegerTypeDisplayType(CharacterConstantDisplayType);
						DefineDataVariable(m_imageBase + debugDir.addressOfRawData, type.Finalize());
						DefineAutoSymbol(new Symbol(DataSymbol, "debugInfoType", m_imageBase + debugDir.addressOfRawData, NoBinding));


						reader.Seek(RVAToFileOffset(debugDir.addressOfRawData));
						uint32_t signature = reader.Read32();
						StoreMetadata("DEBUG_INFO_TYPE", new Metadata((uint64_t)signature), true);
						if (signature == 0x53445352) // SDSR
						{
							vector<uint8_t> guid(16);
							reader.Read(&guid[0], 16);
							uint32_t age = reader.Read32();
							StoreMetadata("PDB_GUID", new Metadata(guid), true);
							StoreMetadata("PDB_AGE", new Metadata((uint64_t)age), true);
							string pdbFileName = reader.ReadCString();
							StoreMetadata("PDB_FILENAME", new Metadata(pdbFileName), true);
							m_logger->LogInfo("PDBFileName: %s\n", pdbFileName.c_str());

							DefineDataVariable(m_imageBase + debugDir.addressOfRawData + 4, Type::ArrayType(Type::IntegerType(1, false), 16));
							DefineAutoSymbol(new Symbol(DataSymbol, "PDBGuid", m_imageBase + debugDir.addressOfRawData + 4, NoBinding));
							DefineDataVariable(m_imageBase + debugDir.addressOfRawData + 20, Type::IntegerType(4, false));
							DefineAutoSymbol(new Symbol(DataSymbol, "PDBAge", m_imageBase + debugDir.addressOfRawData + 20, NoBinding));
							DefineDataVariable(m_imageBase + debugDir.addressOfRawData + 24, Type::ArrayType(Type::IntegerType(1, true), pdbFileName.size() + 1));
							DefineAutoSymbol(new Symbol(DataSymbol, "PDBFileName", m_imageBase + debugDir.addressOfRawData + 24, NoBinding));
						}
					}
					else if (debugDir.type == IMAGE_DEBUG_TYPE_RESERVED10)
					{
						DefineDataVariable(m_imageBase + debugDir.addressOfRawData, Type::IntegerType(4, false));
						DefineAutoSymbol(new Symbol(DataSymbol, "debugTypeReserved", m_imageBase + debugDir.addressOfRawData, NoBinding));
					}
					else
					{
						DefineDataVariable(m_imageBase + debugDir.addressOfRawData, Type::ArrayType(Type::IntegerType(1, false), debugDir.sizeOfData));
						string name = GetDebugTypeName(debugDir.type);
						DefineAutoSymbol(new Symbol(DataSymbol, name, m_imageBase + debugDir.addressOfRawData, NoBinding));
					}
				}

				// Create Debug Directory Type
				StructureBuilder debugDirBuilder;
				debugDirBuilder.AddMember(Type::IntegerType(4, false), "characteristics");
				debugDirBuilder.AddMember(Type::IntegerType(4, false), "timeDateStamp");
				debugDirBuilder.AddMember(Type::IntegerType(2, false), "majorVersion");
				debugDirBuilder.AddMember(Type::IntegerType(2, false), "minorVersion");
				EnumerationBuilder debugType;
				debugType.AddMemberWithValue("IMAGE_DEBUG_TYPE_UNKNOWN", IMAGE_DEBUG_TYPE_UNKNOWN);
				debugType.AddMemberWithValue("IMAGE_DEBUG_TYPE_COFF", IMAGE_DEBUG_TYPE_COFF);
				debugType.AddMemberWithValue("IMAGE_DEBUG_TYPE_CODEVIEW", IMAGE_DEBUG_TYPE_CODEVIEW);
				debugType.AddMemberWithValue("IMAGE_DEBUG_TYPE_FPO", IMAGE_DEBUG_TYPE_FPO);
				debugType.AddMemberWithValue("IMAGE_DEBUG_TYPE_MISC", IMAGE_DEBUG_TYPE_MISC);
				debugType.AddMemberWithValue("IMAGE_DEBUG_TYPE_EXCEPTION", IMAGE_DEBUG_TYPE_EXCEPTION);
				debugType.AddMemberWithValue("IMAGE_DEBUG_TYPE_FIXUP", IMAGE_DEBUG_TYPE_FIXUP);
				debugType.AddMemberWithValue("IMAGE_DEBUG_TYPE_OMAP_TO_SRC", IMAGE_DEBUG_TYPE_OMAP_TO_SRC);
				debugType.AddMemberWithValue("IMAGE_DEBUG_TYPE_OMAP_FROM_SRC", IMAGE_DEBUG_TYPE_OMAP_FROM_SRC);
				debugType.AddMemberWithValue("IMAGE_DEBUG_TYPE_BORLAND", IMAGE_DEBUG_TYPE_BORLAND);
				debugType.AddMemberWithValue("IMAGE_DEBUG_TYPE_RESERVED10", IMAGE_DEBUG_TYPE_RESERVED10);
				debugType.AddMemberWithValue("IMAGE_DEBUG_TYPE_CLSID", IMAGE_DEBUG_TYPE_CLSID);
				debugType.AddMemberWithValue("IMAGE_DEBUG_TYPE_VC_FEATURE", IMAGE_DEBUG_TYPE_VC_FEATURE);
				debugType.AddMemberWithValue("IMAGE_DEBUG_TYPE_POGO", IMAGE_DEBUG_TYPE_POGO);
				debugType.AddMemberWithValue("IMAGE_DEBUG_TYPE_ILTCG", IMAGE_DEBUG_TYPE_ILTCG);
				debugType.AddMemberWithValue("IMAGE_DEBUG_TYPE_MPX", IMAGE_DEBUG_TYPE_MPX);
				debugDirBuilder.AddMember(Type::EnumerationType(debugType.Finalize(), 4), "type");
				debugDirBuilder.AddMember(Type::IntegerType(4, false), "sizeOfData");
				debugDirBuilder.AddMember(Type::IntegerType(4, false), "addressOfRawData");
				debugDirBuilder.AddMember(Type::IntegerType(4, false), "pointerToRawData");

				size_t numDebugEntries = dir.size / 24;
				Ref<Structure> debugDirStruct = debugDirBuilder.Finalize();
				Ref<Type> debugDirType = Type::StructureType(debugDirStruct);
				QualifiedName debugDirName = string("Debug_Directory_Table");
				string debugDirTypeId = Type::GenerateAutoTypeId("pe", debugDirName);
				QualifiedName debugDirTypeName = DefineType(debugDirTypeId, debugDirName, debugDirType);
				DefineDataVariable(m_imageBase + m_dataDirs[IMAGE_DIRECTORY_ENTRY_DEBUG].virtualAddress, Type::ArrayType(Type::NamedType(this, debugDirTypeName), numDebugEntries));
				DefineAutoSymbol(new Symbol(DataSymbol, "__debug_directory_entries", m_imageBase + m_dataDirs[IMAGE_DIRECTORY_ENTRY_DEBUG].virtualAddress, NoBinding));
			}
		}
	}
	catch (std::exception& e)
	{
		m_logger->LogWarn("Failed to parse debug directory: %s\n", e.what());
	}

	try
	{
		if (m_dataDirs.size() > IMAGE_DIRECTORY_ENTRY_TLS)
		{
			PEDataDirectory dir = m_dataDirs[IMAGE_DIRECTORY_ENTRY_TLS];
			if (dir.size != 0)
			{
				reader.Seek(RVAToFileOffset(dir.virtualAddress));
				ImageTLSDirectory tlsEntry;
				if (m_is64)
				{
					tlsEntry.startAddressOfRawData = reader.Read64();
					tlsEntry.endAddressOfRawData = reader.Read64();
					tlsEntry.addressOfIndex = reader.Read64();
					tlsEntry.addressOfCallBacks = reader.Read64();
					tlsEntry.sizeOfZeroFill = reader.Read32();
					tlsEntry.characteristics = reader.Read32();
				}
				else
				{
					tlsEntry.startAddressOfRawData = reader.Read32();
					tlsEntry.endAddressOfRawData = reader.Read32();
					tlsEntry.addressOfIndex = reader.Read32();
					tlsEntry.addressOfCallBacks = reader.Read32();
					tlsEntry.sizeOfZeroFill = reader.Read32();
					tlsEntry.characteristics = reader.Read32();
				}

				m_logger->LogDebug(
					"Parsing IMAGE_DIRECTORY_ENTRY_TLS: %08x\n"
					"\tstartAddressOfRawData %016x\n"
					"\tendAddressOfRawData   %016x\n"
					"\taddressOfIndex        %016x\n"
					"\taddressOfCallBacks    %016x\n"
					"\tsizeOfZeroFill        %08x\n"
					"\tcharacteristics       %08x\n",
					dir.size,
					tlsEntry.startAddressOfRawData,
					tlsEntry.endAddressOfRawData,
					tlsEntry.addressOfIndex,
					tlsEntry.addressOfCallBacks,
					tlsEntry.sizeOfZeroFill,
					tlsEntry.characteristics
				);

				uint64_t address = 0;
				uint32_t i = 0;
				try
				{
					// TODO: I'm pretty sure we're going to have to change this
					// when we deal with relocations properly
					reader.Seek(RVAToFileOffset(tlsEntry.addressOfCallBacks - m_peImageBase));
					while (true)
					{
						if (m_is64)
							address = reader.Read64();
						else
							address = reader.Read32();

						if (address == 0)
							break;

						// This address is a VA, we must handle the relocation by ourselves
						address += (m_imageBase - m_peImageBase);

						char name[64];
						snprintf(name, sizeof(name), "_TLS_Entry_%x", i++);
						if (m_arch)
						{
							if (IsOffsetBackedByFile(address))
							{
								m_logger->LogInfo("Found TLS entrypoint %s: 0x%" PRIx64, name, address);
								Ref<Platform> assPlatform = platform->GetAssociatedPlatformByAddress(address);
								AddPESymbol(FunctionSymbol, "", name, address - m_imageBase);
								auto func = AddFunctionForAnalysis(platform, address);
								AddToEntryFunctions(func);
							}
							else
								m_logger->LogInfo("Found TLS entrypoint %s: 0x%" PRIx64 " however it is not backed by file!",
									name, address);
						}
					}
				}
				catch (std::exception&)
				{
					m_logger->LogWarn("TLS data is malformed");
				}

				// Create TLS Directory Type
				size_t opFieldSize = m_is64 ? 8 : 4;
				StructureBuilder tlsDirBuilder;
				tlsDirBuilder.SetPacked(true);
				tlsDirBuilder.AddMember(Type::IntegerType(opFieldSize, false), "rawDataStartVirtualAddress");
				tlsDirBuilder.AddMember(Type::IntegerType(opFieldSize, false), "rawDataEndVirtualAddress");
				tlsDirBuilder.AddMember(Type::IntegerType(opFieldSize, false), "addressOfIndex");
				tlsDirBuilder.AddMember(Type::IntegerType(opFieldSize, false), "addressOfCallbacks");
				tlsDirBuilder.AddMember(Type::IntegerType(4, false), "sizeOfZeroFill");
				tlsDirBuilder.AddMember(Type::IntegerType(4, false), "characteristics");

				Ref<Structure> tlsDirStruct = tlsDirBuilder.Finalize();
				Ref<Type> tlsDirType = Type::StructureType(tlsDirStruct);
				QualifiedName tlsDirName = string("TLS_Directory");
				string tlsDirTypeId = Type::GenerateAutoTypeId("pe", tlsDirName);
				QualifiedName tlsDirTypeName = DefineType(tlsDirTypeId, tlsDirName, tlsDirType);
				DefineDataVariable(m_imageBase + m_dataDirs[IMAGE_DIRECTORY_ENTRY_TLS].virtualAddress, Type::NamedType(this, tlsDirTypeName));
				DefineAutoSymbol(new Symbol(DataSymbol, "__tls_directory", m_imageBase + m_dataDirs[IMAGE_DIRECTORY_ENTRY_TLS].virtualAddress, NoBinding));
			}
		}
	}
	catch (std::exception& e)
	{
		m_logger->LogWarn("Failed to parse TLS directory: %s\n", e.what());
	}

	try
	{
		PEDataDirectory dir;
		if (m_dataDirs.size() > IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
			dir = m_dataDirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
		else
			dir.virtualAddress = 0;

		if (dir.virtualAddress > 0)
		{
			size_t numImportDelayEntries = 0;

			while (true)
			{
				// Read in next delay directory entry
				reader.Seek(RVAToFileOffset(dir.virtualAddress + (numImportDelayEntries * 32)));
				DelayImportDescriptorEntry entry;
				entry.attributes = reader.Read32();
				entry.name = reader.Read32();
				entry.moduleHandle = reader.Read32();
				entry.delayImportAddressTable = reader.Read32();
				entry.delayImportNameTable = reader.Read32();
				entry.boundDelayImportTable = reader.Read32();
				entry.unloadDelayImportTable = reader.Read32();
				entry.timestamp = reader.Read32();

				if (entry.name == 0)
				{
					if (numImportDelayEntries + 1 != dir.size / 32)
						m_logger->LogWarn(
							"The number of Import_Directory_Table reported by the Data Directories is different from "
							"its correct amount. "
							"There are actually %d Import_Directory_Table in the file, but SizeOfImportTable reports %d. "
							"The PE parsing continues with the actual number of Import_Directory_Table",
							numImportDelayEntries + 1, dir.size / 32);
					break;
				}

				// https://reverseengineering.stackexchange.com/questions/16261/should-the-delay-import-directory-contain-virtual-addresses
				// When the attributes has the lowest bit set, the addresses are RVA.
				// For older binaries, e.g., those generated by VC 6.0, the lowest bit is zero, and the addresses are VA.
				bool isAddrRVA = entry.attributes & PE_DLATTR_RVA;
				if (!isAddrRVA)
				{
					entry.name -= m_imageBase;
					entry.moduleHandle -= m_imageBase;
					entry.delayImportAddressTable -= m_imageBase;
					entry.delayImportNameTable -= m_imageBase;
					entry.boundDelayImportTable -= m_imageBase;
					entry.unloadDelayImportTable -= m_imageBase;
				}

				string entryName = ReadString(entry.name);
				string lowerName = entryName;
				std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
						[](unsigned char c){ return std::tolower(c); });


				vector<Ref<TypeLibrary>> typeLibs = platform->GetTypeLibrariesByName(lowerName);
				for (const auto& typeLib : typeLibs)
				{
					// Check if the type library is already added
					if (GetTypeLibrary(typeLib->GetName()))
						continue;
					AddTypeLibrary(typeLib);

					m_logger->LogDebug("pe: adding type library for '%s': %s (%s)", lowerName.c_str(),
						typeLib->GetName().c_str(), typeLib->GetGuid().c_str());
				}

				Ref<Metadata> ordinals;
				for (const auto& typeLib : typeLibs)
					ordinals = typeLib->QueryMetadata("ordinals");
				if (ordinals && !ordinals->IsKeyValueStore())
					ordinals = nullptr;

				size_t dotPos = entryName.rfind('.');
				string dllName;
				if (dotPos == string::npos)
					dllName = entryName;
				else
					dllName = entryName.substr(0, dotPos);

				// Create Delay Import DLL Name Type
				DefineDataVariable(m_imageBase + entry.name, Type::ArrayType(Type::IntegerType(1, true), entryName.size() + 1));
				DefineAutoSymbol(new Symbol(DataSymbol, "__delay_import_dll_name_" + to_string(numImportDelayEntries) + "(" + dllName + ")", m_imageBase + entry.name, NoBinding));

				// Parse delay import name table
				uint32_t entryOffset = entry.delayImportNameTable;
				uint32_t iatOffset = entry.delayImportAddressTable;
				while (true)
				{
					uint64_t entry;
					bool isOrdinal;
					if (m_is64)
					{
						entry = Read64(entryOffset);
						isOrdinal = (entry & 0x8000000000000000LL) != 0;
						entry &= 0x7fffffffffffffffLL;
						DefineDataVariable(m_imageBase + entryOffset, Type::IntegerType(8, false));
					}
					else
					{
						entry = Read32(entryOffset);
						isOrdinal = (entry & 0x80000000) != 0;
						entry &= 0x7fffffff;
						DefineDataVariable(m_imageBase + entryOffset, Type::IntegerType(4, false));
					}
					m_logger->LogDebug("Entry 0x%llx isOrdinal: %s\n", entry, isOrdinal ? "True" : "False");

					if ((!isOrdinal) && (entry == 0))
						break;

					if (!isAddrRVA)
						entry -= m_imageBase;

					string func;
					uint16_t ordinal;
					if (isOrdinal)
					{
						ordinal = (uint16_t)entry;
						string ordString = to_string(ordinal);
						Ref<Metadata> ordInfo = nullptr;

						if (ordinals)
							ordInfo = ordinals->Get(ordString);

						if (ordInfo && ordInfo->IsString())
							func = ordInfo->GetString();
						else
							func = "Ordinal_" + dllName + "_" + to_string((int)entry);
					}
					else
					{
						ordinal = Read16(entry);
						func = ReadString(entry + 2);
						DefineDataVariable(m_imageBase + entry, Type::IntegerType(2, false));
						DefineAutoSymbol(new Symbol(DataSymbol, "__delay_export_name_ptr_table_" + to_string(numImportDelayEntries) + "(" + dllName + ":" + func + ")", m_imageBase + entry, NoBinding));
						DefineDataVariable(m_imageBase + entry + 2, Type::ArrayType(Type::IntegerType(1, true), func.size() + 1));
						DefineAutoSymbol(new Symbol(DataSymbol, "__delay_import_name_" + to_string(numImportDelayEntries) + "(" + dllName + ":" + func + ")", m_imageBase + entry + 2, NoBinding));
						DefineAutoSymbol(new Symbol(DataSymbol, "__delay_import_lookup_table_" + to_string(numImportDelayEntries) + "(" + dllName + ":" + func + ")", m_imageBase + entryOffset, NoBinding));
					}
					m_logger->LogDebug("FuncString: %s\n", func.c_str());
					AddPESymbol(ImportAddressSymbol, dllName, func, iatOffset, NoBinding, ordinal, typeLibs);
					AddPESymbol(ExternalSymbol, dllName, func, 0, NoBinding, ordinal, typeLibs);
					BNRelocationInfo reloc;
					memset(&reloc, 0, sizeof(reloc));
					reloc.nativeType = -1;
					reloc.address = m_imageBase + iatOffset;
					reloc.size = m_is64 ? 8 : 4;
					reloc.pcRelative = false;
					reloc.base = m_imageBase - m_peImageBase;
					reloc.external = true;
					relocs.push_back({reloc, func});
					entryOffset += m_is64 ? 8 : 4;
					iatOffset += m_is64 ? 8 : 4;
				}

				numImportDelayEntries++;
			}

			if (numImportDelayEntries)
			{
				// Create Delay Import Descriptor Type
				StructureBuilder delayImportDirBuilder;
				delayImportDirBuilder.AddMember(Type::IntegerType(4, false), "attributes");
				delayImportDirBuilder.AddMember(Type::IntegerType(4, false), "name");
				delayImportDirBuilder.AddMember(Type::IntegerType(4, false), "moduleHandle");
				delayImportDirBuilder.AddMember(Type::IntegerType(4, false), "delayImportAddressTable");
				delayImportDirBuilder.AddMember(Type::IntegerType(4, false), "delayImportNameTable");
				delayImportDirBuilder.AddMember(Type::IntegerType(4, false), "boundDelayImportTable");
				delayImportDirBuilder.AddMember(Type::IntegerType(4, false), "unloadDelayImportTable");
				delayImportDirBuilder.AddMember(Type::IntegerType(4, false), "timestamp");

				Ref<Structure> delayImportDirStruct = delayImportDirBuilder.Finalize();
				Ref<Type> delayImportDirType = Type::StructureType(delayImportDirStruct);
				QualifiedName delayImportDirName = string("Delay_Import_Directory");
				string delayImportDirTypeId = Type::GenerateAutoTypeId("pe", delayImportDirName);
				QualifiedName delayImportDirTypeName = DefineType(delayImportDirTypeId, delayImportDirName, delayImportDirType);
				DefineDataVariable(m_imageBase + m_dataDirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].virtualAddress, Type::ArrayType(Type::NamedType(this, delayImportDirTypeName), numImportDelayEntries + 1));
				DefineAutoSymbol(new Symbol(DataSymbol, "__delay_import_directory_entries", m_imageBase + m_dataDirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].virtualAddress, NoBinding));
			}
		}
	}
	catch (std::exception& e)
	{
		m_logger->LogWarn("Failed to parse Delay Import Descriptor directory: %s\n", e.what());
	}

	try
	{
		if ((m_dataDirs.size() > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) && (m_dataDirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].size >= 40))
		{
			reader.Seek(RVAToFileOffset(m_dataDirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].virtualAddress));
			uint32_t loadConfigSize = reader.Read32();
			if (!loadConfigSize || (loadConfigSize > 0x80))
				loadConfigSize = m_dataDirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].size;

			// Create Load Configuration Directory Table Type
			StructureBuilder loadConfigBuilder;
			size_t opFieldSize = m_is64 ? 8 : 4;
			loadConfigBuilder.SetPacked(true);
			loadConfigBuilder.AddMember(Type::IntegerType(4, false), "characteristics");
			loadConfigBuilder.AddMember(Type::IntegerType(4, false), "timeDateStamp");
			loadConfigBuilder.AddMember(Type::IntegerType(2, false), "majorVersion");
			loadConfigBuilder.AddMember(Type::IntegerType(2, false), "minorVersion");
			loadConfigBuilder.AddMember(Type::IntegerType(4, false), "globalFlagsClear");
			loadConfigBuilder.AddMember(Type::IntegerType(4, false), "globalFlagsSet");
			loadConfigBuilder.AddMember(Type::IntegerType(4, false), "criticalSectionDefaultTimeout");
			loadConfigBuilder.AddMember(Type::IntegerType(opFieldSize, false), "deCommitFreeBlockThreshold");
			loadConfigBuilder.AddMember(Type::IntegerType(opFieldSize, false), "deCommitTotalFreeThreshold");
			loadConfigBuilder.AddMember(Type::IntegerType(opFieldSize, false), "lockPrefixTable");
			loadConfigBuilder.AddMember(Type::IntegerType(opFieldSize, false), "maximumAllocationSize");
			loadConfigBuilder.AddMember(Type::IntegerType(opFieldSize, false), "virtualMemoryThreshold");
			loadConfigBuilder.AddMember(Type::IntegerType(opFieldSize, false), "processAffinityMask");
			loadConfigBuilder.AddMember(Type::IntegerType(4, false), "processHeapFlags");
			loadConfigBuilder.AddMember(Type::IntegerType(2, false), "csdVersion");
			loadConfigBuilder.AddMember(Type::IntegerType(2, false), "reserved");
			loadConfigBuilder.AddMember(Type::IntegerType(opFieldSize, false), "editList");
			loadConfigBuilder.AddMember(Type::IntegerType(opFieldSize, false), "securityCookie");

			// 32-bit images specify a size of 0x40 for compatability reasons
			size_t curSize = (m_is64 ? 0x70 : 0x40);
			vector<pair<Ref<Type>, string>> fields = {
				{Type::IntegerType(opFieldSize, false), "seHandlerTable" },
				{Type::IntegerType(opFieldSize, false), "seHandlerCount" },
				{Type::IntegerType(opFieldSize, false), "guardCFCheckFunctionPointer" },
				{Type::IntegerType(opFieldSize, false), "guardCFDispatchFunctionPointer" },
				{Type::IntegerType(opFieldSize, false), "guardCFFunctionTable" },
				{Type::IntegerType(opFieldSize, false), "guardCFFunctionCount" },
				{Type::IntegerType(4, false), "guardFlags" },
				{Type::IntegerType(2, false), "Flags" },
				{Type::IntegerType(2, false), "Catalog" },
				{Type::IntegerType(4, false), "CatalogOffset" },
				{Type::IntegerType(4, false), "Reserved" },
				{Type::IntegerType(opFieldSize, false), "guardAddressTakenIatEntryTable" },
				{Type::IntegerType(opFieldSize, false), "guardAddressTakenIatEntryCount" },
				{Type::IntegerType(opFieldSize, false), "guardLongJumpTargetTable" },
				{Type::IntegerType(opFieldSize, false), "guardLongJumpTargetCount" },
				{Type::IntegerType(opFieldSize, false), "dynamicValueRelocTable" },
				{Type::IntegerType(opFieldSize, false), "CHPEMetadataPointer" },
				{Type::IntegerType(opFieldSize, false), "guardRFFailureRoutine" },
				{Type::IntegerType(opFieldSize, false), "guardRFFailureRoutineFunctionPointer" },
				{Type::IntegerType(4, false), "dynamicValueRelocTableOffset" },
				{Type::IntegerType(2, false), "dynamicValueRelocTableSection" },
				{Type::IntegerType(2, false), "reserved2" },
				{Type::IntegerType(opFieldSize, false), "guardRFVerifyStackPointerFunctionPointer" },
				{Type::IntegerType(4, false), "hotPatchTableOffset" },
				{Type::IntegerType(4, false), "reserved3" },
				{Type::IntegerType(opFieldSize, false), "enclaveConfigurationPointer" },
				{Type::IntegerType(opFieldSize, false), "volatileMetadataPointer" },
				{Type::IntegerType(opFieldSize, false), "guardEHContinuationTable" },
				{Type::IntegerType(opFieldSize, false), "guardEHContinuationCount" },
				{Type::IntegerType(opFieldSize, false), "guardXFGCheckFunctionPointer" },
				{Type::IntegerType(opFieldSize, false), "guardXFGDispatchFunctionPointer" },
				{Type::IntegerType(opFieldSize, false), "guardXFGTableDispatchFunctionPointer" },
				{Type::IntegerType(opFieldSize, false), "castGuardOsDeterminedFailureMode" },
				{Type::IntegerType(opFieldSize, false), "guardMemcpyFunctionPointer" }
			};

			for (const auto& [type, name] : fields)
			{
				curSize += type->GetWidth();
				if (curSize > loadConfigSize)
					break;
				loadConfigBuilder.AddMember(type, name);
			}

			Ref<Structure> loadConfigStruct = loadConfigBuilder.Finalize();
			Ref<Type> loadConfigType = Type::StructureType(loadConfigStruct);
			QualifiedName loadConfigName = string("Load_Configuration_Directory_Table");
			string loadConfigTypeId = Type::GenerateAutoTypeId("pe", loadConfigName);
			QualifiedName loadConfigTypeName = DefineType(loadConfigTypeId, loadConfigName, loadConfigType);
			DefineDataVariable(m_imageBase + m_dataDirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].virtualAddress, Type::NamedType(this, loadConfigTypeName));
			DefineAutoSymbol(new Symbol(DataSymbol, "__load_configuration_directory_table", m_imageBase + m_dataDirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].virtualAddress, NoBinding));

			// parse securityCookie
			size_t securityCookieOffset = m_is64 ? 88 : 60;
			reader.Seek(RVAToFileOffset(m_dataDirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].virtualAddress + securityCookieOffset));
			auto securityCookieAddress = m_is64 ? reader.Read64() : reader.Read32();
			// The securityCookieAddress reported by the file is a VA, which does not account for rebase. We must
			// calculate the rebased value for it.
			securityCookieAddress += (m_imageBase - m_peImageBase);
			m_logger->LogDebug("securityCookieAddress: 0x%" PRIx64, securityCookieAddress);
			DefineDataVariable(securityCookieAddress, Type::IntegerType(m_is64 ? 8 : 4, false));
			DefineAutoSymbol(new Symbol(DataSymbol, "__security_cookie", securityCookieAddress, NoBinding));

			// parse SEH table
			size_t seHandlerTableTableOffset = m_is64 ? 96 : 64;
			reader.Seek(RVAToFileOffset(m_dataDirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].virtualAddress + seHandlerTableTableOffset));
			uint64_t seHandlerTable = m_is64 ? reader.Read64() : reader.Read32();
			seHandlerTable += (m_imageBase - m_peImageBase);
			m_logger->LogDebug("seHandlerTable: 0x%" PRIx64, seHandlerTable);
			uint64_t seHandlerCount = m_is64 ? reader.Read64() : reader.Read32();
			if (seHandlerTable && seHandlerCount)
			{
				DefineDataVariable(seHandlerTable, Type::ArrayType(Type::IntegerType(4, false), seHandlerCount));
				DefineAutoSymbol(new Symbol(DataSymbol, "__seh_table", seHandlerTable, NoBinding));

				bool processSehTable = true;
				if (settings && settings->Contains("loader.pe.processSehTable"))
					processSehTable = settings->Get<bool>("loader.pe.processSehTable", this);
				if (processSehTable)
				{
					reader.Seek(RVAToFileOffset(seHandlerTable - m_imageBase));
					for (size_t i = 0; i < seHandlerCount; i++)
					{
						uint64_t sehEntry = m_imageBase + reader.Read32();
						Ref<Platform> targetPlatform = platform->GetAssociatedPlatformByAddress(sehEntry);
						AddFunctionForAnalysis(targetPlatform, sehEntry);
						// TODO possibly auto name these entries
						//DefineAutoSymbol(new Symbol(FunctionSymbol, "__seh_entry_" + to_string(i), sehEntry));
					}
				}
			}

			// parse CFG table
			if ((loadConfigSize >= (uint32_t)(m_is64 ? 0x94 : 0x40)) && (m_is64 || (opt.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)))
			{
				size_t cfgFields = m_is64 ? 112 : 72;
				reader.Seek(RVAToFileOffset(m_dataDirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].virtualAddress + cfgFields));

				uint64_t guardCFCheckFunctionPointer = m_is64 ? reader.Read64() : reader.Read32();
				if (guardCFCheckFunctionPointer != 0)
				{
					guardCFCheckFunctionPointer += (m_imageBase - m_peImageBase);
					m_logger->LogDebug("guardCFCheckFunctionPointer: 0x%" PRIx64, guardCFCheckFunctionPointer);
				}
				uint64_t guardCFDispatchFunctionPointer = m_is64 ? reader.Read64() : reader.Read32();
				if (guardCFDispatchFunctionPointer != 0)
				{
					guardCFDispatchFunctionPointer += (m_imageBase - m_peImageBase);
					m_logger->LogDebug("guardCFDispatchFunctionPointer: 0x%" PRIx64, guardCFDispatchFunctionPointer);
				}
				uint64_t guardCFFunctionTable = m_is64 ? reader.Read64() : reader.Read32();
				uint64_t guardCFFunctionCount = m_is64 ? reader.Read64() : reader.Read32();
				uint32_t guardFlags = reader.Read32();

				uint64_t guardCFCheckFunction = 0;
				if (guardCFCheckFunctionPointer != 0)
				{
					reader.Seek(RVAToFileOffset(guardCFCheckFunctionPointer - m_imageBase));
					guardCFCheckFunction = m_is64 ? reader.Read64() : reader.Read32();
					guardCFCheckFunction += (m_imageBase - m_peImageBase);
				}

				uint64_t guardCFDispatchFunction = 0;
				if (guardCFDispatchFunctionPointer != 0)
				{
					reader.Seek(RVAToFileOffset(guardCFDispatchFunctionPointer - m_imageBase));
					guardCFDispatchFunction = m_is64 ? reader.Read64() : reader.Read32();
					guardCFDispatchFunction += (m_imageBase - m_peImageBase);
				}

				auto functionPointer = Type::PointerType(platform->GetArchitecture(), Type::FunctionType(Type::VoidType(), platform->GetDefaultCallingConvention(), {}));
				auto guardCFCheckFunctionType = Type::FunctionType(Type::VoidType(),
					platform->GetDefaultCallingConvention(),
					{
						FunctionParameter("", functionPointer)
					});
				auto pointerGuardCFCheckFunctionType = Type::PointerType(platform->GetArchitecture(), guardCFCheckFunctionType);

				if (guardCFCheckFunctionPointer != 0)
				{
					auto guardCFCheckPointerSymbol = new Symbol(DataSymbol, "__guard_check_icall_fptr", guardCFCheckFunctionPointer, NoBinding);
					DefineAutoSymbolAndVariableOrFunction(GetDefaultPlatform(), guardCFCheckPointerSymbol, pointerGuardCFCheckFunctionType);
				}

				if (guardCFDispatchFunctionPointer != 0)
				{
					auto guardCFCheckDispatchSymbol = new Symbol(DataSymbol, "__guard_dispatch_icall_fptr", guardCFDispatchFunctionPointer, NoBinding);
					DefineAutoSymbolAndVariableOrFunction(GetDefaultPlatform(), guardCFCheckDispatchSymbol, pointerGuardCFCheckFunctionType);
				}

				if (guardCFCheckFunction != 0)
				{
					auto guardCFCheckSymbol = new Symbol(FunctionSymbol, "_guard_check_icall", guardCFCheckFunction, NoBinding);
					DefineAutoSymbolAndVariableOrFunction(GetDefaultPlatform(), guardCFCheckSymbol, guardCFCheckFunctionType);
				}

				if (guardCFDispatchFunction != 0)
				{
					auto guardCFDispatchSymbol = new Symbol(FunctionSymbol, "_guard_dispatch_icall_nop", guardCFDispatchFunction, NoBinding);
					DefineAutoSymbolAndVariableOrFunction(GetDefaultPlatform(), guardCFDispatchSymbol, guardCFCheckFunctionType);
				}

				if (guardFlags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT)
				{
					size_t mdSize = ((guardFlags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT);

					// Create GFIDS Table Type
					if (mdSize)
					{
						StructureBuilder gfidsBuilder;
						gfidsBuilder.SetPacked(true);
						gfidsBuilder.AddMember(Type::IntegerType(4, false), "rvAddr");
						gfidsBuilder.AddMember(Type::IntegerType(mdSize, false), "metadata");

						Ref<Structure> gfidsStruct = gfidsBuilder.Finalize();
						Ref<Type> gfidsTableType = Type::StructureType(gfidsStruct);
						QualifiedName gfidsTableName = string("Guard_Control_Flow_Function_Table");
						string gfidsTypeId = Type::GenerateAutoTypeId("pe", gfidsTableName);
						QualifiedName gfidsTypeName = DefineType(gfidsTypeId, gfidsTableName, gfidsTableType);
						DefineDataVariable(guardCFFunctionTable, Type::ArrayType(Type::NamedType(this, gfidsTypeName), guardCFFunctionCount));
						DefineAutoSymbol(new Symbol(DataSymbol, "__gfids_table", guardCFFunctionTable, NoBinding));
					}
					else
					{
						DefineDataVariable(guardCFFunctionTable, Type::ArrayType(Type::IntegerType(4, false), guardCFFunctionCount));
						DefineAutoSymbol(new Symbol(DataSymbol, "__gfids_table", guardCFFunctionTable, NoBinding));
					}

					bool processCfgTable = true;
					if (settings && settings->Contains("loader.pe.processCfgTable"))
						processCfgTable = settings->Get<bool>("loader.pe.processCfgTable", this);
					if (processCfgTable)
					{
						reader.Seek(RVAToFileOffset(guardCFFunctionTable - m_peImageBase));
						for (size_t i = 0; i < guardCFFunctionCount; i++)
						{
							uint64_t cfgAddr = m_imageBase + reader.Read32();
							Ref<Platform> targetPlatform = platform->GetAssociatedPlatformByAddress(cfgAddr);
							AddFunctionForAnalysis(targetPlatform, cfgAddr);
							for (size_t mdIdx = 0; mdIdx < mdSize; mdIdx++)
							{
								auto value = reader.Read8();
								if (mdIdx == 0 && (value & IMAGE_GUARD_FLAG_FID_XFG) != 0)
								{
									DefineDataVariable(cfgAddr - 8, Type::IntegerType(8, false));
								}
							}
						}
					}
				}
			}
		}
	}
	catch (std::exception& e)
	{
		m_logger->LogWarn("Failed to parse load configuration directory: %s\n", e.what());
	}

	try
	{
		if ((m_dataDirs.size() > IMAGE_DIRECTORY_ENTRY_EXPORT) && (m_dataDirs[IMAGE_DIRECTORY_ENTRY_EXPORT].size >= 40))
		{
			PEExportDirectory dir;
			reader.Seek(RVAToFileOffset(m_dataDirs[IMAGE_DIRECTORY_ENTRY_EXPORT].virtualAddress));
			dir.characteristics = reader.Read32();
			dir.timestamp = reader.Read32();
			dir.majorVersion = reader.Read16();
			dir.minorVersion = reader.Read16();
			dir.dllNameAddress = reader.Read32();
			dir.base = reader.Read32();
			dir.functionCount = reader.Read32();
			dir.nameCount = reader.Read32();
			dir.addressOfFunctions = reader.Read32();
			dir.addressOfNames = reader.Read32();
			dir.addressOfNameOrdinals = reader.Read32();

			// Create Export Directory Table Type
			StructureBuilder exportDirBuilder;
			exportDirBuilder.SetPacked(true);
			exportDirBuilder.AddMember(Type::IntegerType(4, false), "exportFlags");
			exportDirBuilder.AddMember(Type::IntegerType(4, false), "timeDateStamp");
			exportDirBuilder.AddMember(Type::IntegerType(2, false), "majorVersion");
			exportDirBuilder.AddMember(Type::IntegerType(2, false), "minorVersion");
			exportDirBuilder.AddMember(Type::IntegerType(4, false), "nameRva");
			exportDirBuilder.AddMember(Type::IntegerType(4, false), "ordinalBase");
			exportDirBuilder.AddMember(Type::IntegerType(4, false), "addressTableEntries");
			exportDirBuilder.AddMember(Type::IntegerType(4, false), "numberOfNamePointers");
			exportDirBuilder.AddMember(Type::IntegerType(4, false), "exportAddressTableRva");
			exportDirBuilder.AddMember(Type::IntegerType(4, false), "namePointerRva");
			exportDirBuilder.AddMember(Type::IntegerType(4, false), "ordinalTableRva");

			Ref<Structure> exportDirStruct = exportDirBuilder.Finalize();
			Ref<Type> exportDirType = Type::StructureType(exportDirStruct);
			QualifiedName exportDirName = string("Export_Directory_Table");
			string exportDirTypeId = Type::GenerateAutoTypeId("pe", exportDirName);
			QualifiedName exportDirTypeName = DefineType(exportDirTypeId, exportDirName, exportDirType);
			DefineDataVariable(m_imageBase + m_dataDirs[IMAGE_DIRECTORY_ENTRY_EXPORT].virtualAddress, Type::NamedType(this, exportDirTypeName));
			DefineAutoSymbol(new Symbol(DataSymbol, "__export_directory_table", m_imageBase + m_dataDirs[IMAGE_DIRECTORY_ENTRY_EXPORT].virtualAddress, NoBinding));

			// Read name of imported DLL, and trim extension for creating symbol name
			string dllName = ReadString(dir.dllNameAddress);
			size_t strPos = dllName.rfind('.');
			string dllShortName = (strPos != string::npos) ? dllName.substr(0, strPos) : dllName;
			DefineDataVariable(m_imageBase + dir.dllNameAddress, Type::ArrayType(Type::IntegerType(1, true), dllName.size() + 1));
			DefineAutoSymbol(new Symbol(DataSymbol, "__pe_" + dllShortName + "_export_dll_name", m_imageBase + dir.dllNameAddress, NoBinding));

			string tableName = "__pe_" + dllShortName + "_export_address_table";
			DefineDataVariable(m_imageBase + dir.addressOfFunctions, Type::ArrayType(Type::IntegerType(4, false), dir.functionCount));
			DefineAutoSymbol(new Symbol(DataSymbol, tableName, m_imageBase + dir.addressOfFunctions, NoBinding));

			vector<uint32_t> funcs;
			reader.Seek(RVAToFileOffset(dir.addressOfFunctions));
			funcs.reserve(dir.functionCount);
			for (uint32_t i = 0; i < dir.functionCount; i++)
				funcs.push_back(reader.Read32());

			vector<uint32_t> nameAddrs;
			if (dir.addressOfNames != 0)
			{
				string tableName = "__pe_" + dllShortName + "_export_name_pointer_table";
				DefineDataVariable(m_imageBase + dir.addressOfNames, Type::ArrayType(Type::IntegerType(4, false), dir.nameCount));
				DefineAutoSymbol(new Symbol(DataSymbol, tableName, m_imageBase + dir.addressOfNames, NoBinding));

				nameAddrs.reserve(dir.nameCount);
				reader.Seek(RVAToFileOffset(dir.addressOfNames));
				for (uint32_t i = 0; i < dir.nameCount; i++)
					nameAddrs.push_back(reader.Read32());
			}

			vector<uint16_t> nameOrdinals;
			if (dir.addressOfNameOrdinals != 0)
			{
				string tableName = "__pe_" + dllShortName + "_export_ordinal_table";
				DefineDataVariable(m_imageBase + dir.addressOfNameOrdinals, Type::ArrayType(Type::IntegerType(2, false), dir.nameCount));
				DefineAutoSymbol(new Symbol(DataSymbol, tableName, m_imageBase + dir.addressOfNameOrdinals, NoBinding));

				nameOrdinals.reserve(dir.nameCount);
				reader.Seek(RVAToFileOffset(dir.addressOfNameOrdinals));
				for (uint32_t i = 0; i < dir.nameCount; i++)
					nameOrdinals.push_back(reader.Read16());
			}

			map<uint16_t, string> namesByOrdinal;
			for (uint32_t i = 0; i < dir.nameCount; i++)
			{
				if (i >= nameOrdinals.size())
					break;
				if (i >= nameAddrs.size())
					break;

				string name = ReadString(nameAddrs[i]);
				namesByOrdinal[nameOrdinals[i]] = name;

				DefineDataVariable(m_imageBase + nameAddrs[i], Type::ArrayType(Type::IntegerType(1, true), name.size() + 1));
				DefineAutoSymbol(new Symbol(DataSymbol, "__export_name(" + name + ")", m_imageBase + nameAddrs[i], NoBinding));
			}

			// Create symbols for the exports
			uint32_t exportTableStart = m_dataDirs[IMAGE_DIRECTORY_ENTRY_EXPORT].virtualAddress;
			uint32_t exportTableEnd = exportTableStart + m_dataDirs[IMAGE_DIRECTORY_ENTRY_EXPORT].size;
			for (uint32_t i = 0; i < dir.functionCount; i++)
			{
				uint32_t rvAddr = funcs[i];
				if (rvAddr == 0)
					continue;
				string name;
				auto nameIter = namesByOrdinal.find(i);
				if (nameIter == namesByOrdinal.end())
				{
					char buff[32];
					snprintf(buff, sizeof(buff), "ordinal_%u", i + dir.base);
					name = buff;
				}
				else
				{
					name = nameIter->second;
				}
				uint32_t characteristics = GetRVACharacteristics(rvAddr);

				if ((rvAddr >= exportTableStart) && (rvAddr < exportTableEnd))
				{
					string forwarderName = ReadString(rvAddr);
					DefineDataVariable(m_imageBase + rvAddr, Type::ArrayType(Type::IntegerType(1, true), forwarderName.size() + 1));
					DefineAutoSymbol(new Symbol(DataSymbol, "__forwarder_name(" + forwarderName + ")", m_imageBase + rvAddr, GlobalBinding,
						NameSpace(DEFAULT_INTERNAL_NAMESPACE), i + dir.base));
				}
				else
				{
					if ((characteristics & (PE_ATTR_CODE | PE_ATTR_EXEC)) != 0)
						AddPESymbol(FunctionSymbol, "", name, rvAddr, GlobalBinding, i + dir.base);
					else if (characteristics != 0)
						AddPESymbol(DataSymbol, "", name, rvAddr, GlobalBinding, i + dir.base);
					//else // TODO need to handle other data symbols
				}
			}
		}
	}
	catch (std::exception& e)
	{
		m_logger->LogWarn("Failed to parse export directory: %s\n", e.what());
	}

	m_symbolQueue->Process();
	delete m_symbolQueue;
	m_symbolQueue = nullptr;

	EndBulkModifySymbols();

	StoreMetadata("SymbolExternalLibraryMapping", m_symExternMappingMetadata, true);

	try
	{
		if (m_dataDirs.size() > IMAGE_DIRECTORY_ENTRY_BASERELOC)
		{
			PEDataDirectory dir = m_dataDirs[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			// Check if there is a '.reloc' section that is different than this directory entry
			vector<PEDataDirectory> dirs = { m_dataDirs[IMAGE_DIRECTORY_ENTRY_BASERELOC]};
			auto section = find_if(m_sections.begin(), m_sections.end(), [](const PESection& section) { return section.name == ".reloc"; });
			if (section != m_sections.end())
			{
				if (section->virtualAddress != dir.virtualAddress)
					dirs.push_back({ section->virtualAddress, section->sizeOfRawData });
			}
			for (auto& dir : dirs)
			{
				if (dir.size == 0 || dir.virtualAddress == 0)
					continue;

				reader.Seek(RVAToFileOffset(dir.virtualAddress));
				uint64_t size = 0;
				while (size < dir.size)
				{
					ImageBaseRelocation baseReloc;
					baseReloc.VirtualAddress = reader.Read32() + m_imageBase;
					baseReloc.SizeOfBlock = reader.Read32();
					if (baseReloc.SizeOfBlock < 8)
						break;
					if (baseReloc.SizeOfBlock == 8)
					{
						size += baseReloc.SizeOfBlock;
						continue;
					}
					size_t nEntries = (baseReloc.SizeOfBlock - 8) / sizeof(uint16_t);
					uint16_t* relocEntries = new uint16_t[nEntries];
					if (relocEntries)
					{
						reader.Read(relocEntries, nEntries * sizeof(uint16_t));
						for (size_t i = 0; i < nEntries; i++)
						{
							BNRelocationInfo reloc;
							memset(&reloc, 0, sizeof(reloc));
							reloc.nativeType = relocEntries[i] >> 12;
							if (!reloc.nativeType) // IMAGE_REL_BASED_ABSOLUTE relocations are skipped/used for padding
								continue;
							reloc.address = baseReloc.VirtualAddress + (relocEntries[i] & 0xfff);
							reloc.size = m_is64 ? 8 : 4;
							reloc.pcRelative = false;
							reloc.base = m_imageBase - m_peImageBase;
							DefineRelocation(m_arch, reloc, 0, reloc.address);
						}
						delete[] relocEntries;
					}
					size += baseReloc.SizeOfBlock;
				}
			}
		}
	}
	catch (std::exception& e)
	{
		m_logger->LogWarn("Failed to parse relocation directory: %s\n", e.what());
	}

	for (auto& [reloc, name] : relocs)
	{
		if (auto symbol = GetSymbolByRawName(name, GetExternalNameSpace()); symbol)
			DefineRelocation(m_arch, reloc, symbol, reloc.address);
	}

	try
	{
		//TODO: properly name tables, entries, data entries

		PEDataDirectory dir;
		// Read resource directory
		if (m_dataDirs.size() > IMAGE_DIRECTORY_ENTRY_RESOURCE)
			dir = m_dataDirs[IMAGE_DIRECTORY_ENTRY_RESOURCE];
		else
			dir.virtualAddress = 0;

		if (dir.virtualAddress > 0)
		{
			// Create Resource Directory Table Type
			StructureBuilder resourceDirTableBuilder;
			resourceDirTableBuilder.AddMember(Type::IntegerType(4, false), "characteristics");
			resourceDirTableBuilder.AddMember(Type::IntegerType(4, false), "timeDateStamp");
			resourceDirTableBuilder.AddMember(Type::IntegerType(2, false), "majorVersion");
			resourceDirTableBuilder.AddMember(Type::IntegerType(2, false), "minorVersion");
			resourceDirTableBuilder.AddMember(Type::IntegerType(2, false), "numNameEntries");
			resourceDirTableBuilder.AddMember(Type::IntegerType(2, false), "numIdEntries");

			Ref<Structure> resourceTableStruct = resourceDirTableBuilder.Finalize();
			Ref<Type> resourceDirTableType = Type::StructureType(resourceTableStruct);
			QualifiedName resourceDirTableName = string("Resource_Directory_Table");
			string resourceDirTableTypeId = Type::GenerateAutoTypeId("pe", resourceDirTableName);
			QualifiedName resourceDirTableTypeName = DefineType(resourceDirTableTypeId, resourceDirTableName, resourceDirTableType);

			// Create Resource Directory Entry Type
			StructureBuilder resourceDirEntryBuilder;
			resourceDirEntryBuilder.AddMember(Type::IntegerType(4, false), "id");
			resourceDirEntryBuilder.AddMember(Type::IntegerType(4, false), "offset");

			Ref<Structure> resourceDirEntryStruct = resourceDirEntryBuilder.Finalize();
			Ref<Type> resourceDirEntryType = Type::StructureType(resourceDirEntryStruct);
			QualifiedName resourceDirEntryName = string("Resource_Directory_Table_Entry");
			string resourceDirEntryTypeId = Type::GenerateAutoTypeId("pe", resourceDirEntryName);
			QualifiedName resourceDirEntryTypeName = DefineType(resourceDirEntryTypeId, resourceDirEntryName, resourceDirEntryType);

			// Create Resource Data Entry Type
			StructureBuilder resourceDataEntryBuilder;
			resourceDataEntryBuilder.AddMember(Type::IntegerType(4, false), "dataRva");
			resourceDataEntryBuilder.AddMember(Type::IntegerType(4, false), "dataSize");
			resourceDataEntryBuilder.AddMember(Type::IntegerType(4, false), "codepage");
			resourceDataEntryBuilder.AddMember(Type::IntegerType(4, false), "reserved");

			Ref<Structure> resourceDataEntryStruct = resourceDataEntryBuilder.Finalize();
			Ref<Type> resourceDataEntryType = Type::StructureType(resourceDataEntryStruct);
			QualifiedName resourceDataEntryName = string("Resource_Data_Entry");
			string resourceDataEntryTypeId = Type::GenerateAutoTypeId("pe", resourceDataEntryName);
			QualifiedName resourceDataEntryTypeName = DefineType(resourceDataEntryTypeId, resourceDataEntryName, resourceDataEntryType);

			std::list<uint64_t> tableAddrsToParse = {dir.virtualAddress};

			uint32_t resourceDirectoryTableNum = 0;
			while (!tableAddrsToParse.empty())
			{
				uint64_t tableAddr = tableAddrsToParse.front();
				tableAddrsToParse.pop_front();
				// Read in next directory entry
				reader.Seek(RVAToFileOffset(tableAddr));
				PEResourceDirectoryTable importDirTable;
				importDirTable.characteristics = reader.Read32();
				importDirTable.timeDateStamp = reader.Read32();
				importDirTable.majorVersion = reader.Read16();
				importDirTable.minorVersion = reader.Read16();
				importDirTable.numNameEntries = reader.Read16();
				importDirTable.numIdEntries = reader.Read16();

				DefineDataVariable(m_imageBase + tableAddr, Type::NamedType(this, resourceDirTableTypeName));
				DefineAutoSymbol(new Symbol(DataSymbol, fmt::format("__resource_directory_table_{}", resourceDirectoryTableNum), m_imageBase + tableAddr, NoBinding));

				// All the Name entries precede all the ID entries for the table but we treat them the same
				// All entries for the table are sorted in ascending order: the Name entries by case-sensitive string and the ID entries by numeric value.
				// Offsets are relative to the address in the IMAGE_DIRECTORY_ENTRY_RESOURCE DataDirectory.

				// Offset value:
				// High bit 0. Address of a Resource Data entry (a leaf).
				// High bit 1. The lower 31 bits are the address of another resource directory table (the next level down).

				std::vector<size_t> dataEntryOffsets;

				size_t numTableEntries = importDirTable.numNameEntries + importDirTable.numIdEntries;

				if (numTableEntries > 0)
				{
					for (size_t entryNum = 0; entryNum < numTableEntries; entryNum++)
					{
						PEResourceDirectoryEntry importDirEntry;
						importDirEntry.id = reader.Read32();
						importDirEntry.offset = reader.Read32();

						if (importDirEntry.id & 0x80000000)
						{
							// Name entry
							// First 2 bytes of name are length

							size_t nameAddr = dir.virtualAddress + (importDirEntry.id ^ 0x80000000);

							BinaryReader nameReader(GetParentView(), LittleEndian);
							nameReader.Seek(RVAToFileOffset(nameAddr));

							uint16_t nameLen = nameReader.Read16();
							// Plus 2 because it's length-prefixed
							DefineDataVariable(m_imageBase + nameAddr + 2, Type::ArrayType(Type::WideCharType(2), nameLen));
						}

						if (importDirEntry.offset & 0x80000000)
						{
							// Lower 31 bits are address of another table
							tableAddrsToParse.push_back(dir.virtualAddress + (importDirEntry.offset ^ 0x80000000));
						}
						else
						{
							// Address of data entry
							dataEntryOffsets.push_back(importDirEntry.offset);
						}
					}

					size_t tableEntriesStart = m_imageBase + tableAddr + sizeof(PEResourceDirectoryTable);
					DefineDataVariable(tableEntriesStart, Type::ArrayType(Type::NamedType(this, resourceDirEntryTypeName), numTableEntries));
					DefineAutoSymbol(new Symbol(DataSymbol, fmt::format("__resource_directory_table_{}_entries", resourceDirectoryTableNum), tableEntriesStart, NoBinding));
				}

				for(size_t dataEntryNum = 0; dataEntryNum < dataEntryOffsets.size(); dataEntryNum++)
				{
					BinaryReader entryReader(GetParentView(), LittleEndian);

					size_t entryOffset = dataEntryOffsets[dataEntryNum];
					entryReader.Seek(RVAToFileOffset(dir.virtualAddress + entryOffset));
					PEResourceDataEntry dataEntry;
					dataEntry.dataRva = entryReader.Read32();
					dataEntry.dataSize = entryReader.Read32();
					dataEntry.dataCodePage = entryReader.Read32();
					dataEntry.reserved = entryReader.Read32();

					if (dataEntry.reserved != 0)
					{
						// Invalid entry, this needs to be 0
						continue;
					}

					size_t entryAddr = m_imageBase + dir.virtualAddress + entryOffset;

					DefineDataVariable(entryAddr, Type::NamedType(this, resourceDataEntryTypeName));
					DefineAutoSymbol(new Symbol(DataSymbol, fmt::format("__resource_directory_table_{}_data_entry_{}", resourceDirectoryTableNum, dataEntryNum), entryAddr, NoBinding));

					//TODO: properly name based on path taken to get here
					DefineDataVariable(m_imageBase + dataEntry.dataRva, Type::ArrayType(Type::IntegerType(1, true), dataEntry.dataSize));
				}

				resourceDirectoryTableNum++;
			}
		}
	}
	catch (std::exception& e)
	{
		m_logger->LogWarn("Failed to parse resource directory: %s\n", e.what());
	}

	Ref<Settings> programSettings = Settings::Instance();
	if (programSettings->Contains("core.function.analyzeConditionalNoReturns") &&
		opt.subsystem != IMAGE_SUBSYSTEM_NATIVE && (
			GetSymbolByRawName("TerminateProcess", GetExternalNameSpace()) ||
			GetSymbolByRawName("_TerminateProcess@8", GetExternalNameSpace())))
	{
		// TerminateProcess is imported and this is a user mode file
		programSettings->Set("corePlugins.workflows.conditionalNoReturn", true);
	}

	// Add a symbol for the entry point
	if (m_entryPoint)
		DefineAutoSymbol(new Symbol(FunctionSymbol, "_start", m_imageBase + m_entryPoint));
	std::chrono::steady_clock::time_point endTime = std::chrono::steady_clock::now();
	double t = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count() / 1000.0;
	m_logger->LogInfo("PE parsing took %.3f seconds\n", t);

	return true;
}


uint64_t PEView::RVAToFileOffset(uint64_t offset, bool except)
{
	for (auto& i : m_sections)
	{
		if ((offset >= i.virtualAddress) &&
			(offset < (i.virtualAddress + i.sizeOfRawData)) && (i.virtualSize != 0))
		{
			uint64_t progOfs = offset - i.virtualAddress;
			return i.pointerToRawData + progOfs;
		}
	}

	if (!except)
		return offset;

	throw PEFormatException("encountered invalid offset");
}


uint32_t PEView::GetRVACharacteristics(uint64_t offset)
{
	for (auto& i : m_sections)
	{
		if ((offset >= i.virtualAddress) && (offset < (i.virtualAddress + i.virtualSize)) && (i.virtualSize != 0))
			return i.characteristics;
	}
	return 0;
}


string PEView::ReadString(uint64_t rva)
{
	uint64_t offset = RVAToFileOffset(rva);
	string result;
	char data[STRING_READ_CHUNK_SIZE];
	while (true)
	{
		size_t len = GetParentView()->Read(data, offset, STRING_READ_CHUNK_SIZE);
		if (len == 0)
			break;

		size_t i;
		for (i = 0; i < len; i++)
		{
			if (data[i] == 0)
				break;
		}

		result += string(&data[0], &data[i]);
		if (i < len)
			break;
		offset += len;
	}
	return result;
}


uint16_t PEView::Read16(uint64_t rva)
{
	uint64_t ofs = RVAToFileOffset(rva);
	BinaryReader reader(GetParentView(), LittleEndian);
	reader.Seek(ofs);
	return reader.Read16();
}


uint32_t PEView::Read32(uint64_t rva)
{
	uint64_t ofs = RVAToFileOffset(rva);
	BinaryReader reader(GetParentView(), LittleEndian);
	reader.Seek(ofs);
	return reader.Read32();
}


uint64_t PEView::Read64(uint64_t rva)
{
	uint64_t ofs = RVAToFileOffset(rva);
	BinaryReader reader(GetParentView(), LittleEndian);
	reader.Seek(ofs);
	return reader.Read64();
}


// The addr is RVA
void PEView::AddPESymbol(BNSymbolType type, const string& dll, const string& name, uint64_t addr,
		BNSymbolBinding binding, uint64_t ordinal, vector<Ref<TypeLibrary>> libs)
{
	// Don't create symbols that are present in the database snapshot now
	if (type != ExternalSymbol && m_backedByDatabase)
		return;

	// If name is empty, symbol is not valid
	if (name.size() == 0)
		return;

	// Ensure symbol is within the executable
	if (type != ExternalSymbol)
	{
		bool ok = false;
		for (auto& i : m_sections)
		{
			if ((addr >= i.virtualAddress) && (addr < (i.virtualAddress + i.virtualSize)))
			{
				ok = true;
				break;
			}
		}
		if (!ok)
			return;
	}

	auto address = type == ExternalSymbol ? addr : m_imageBase + addr;
	Ref<Type> symbolTypeRef;

	if (libs.size() && ((type == ExternalSymbol) || (type == ImportAddressSymbol) || (type == ImportedDataSymbol)))
	{
		QualifiedName n(name);
		for (auto lib : libs)
		{
			Ref<TypeLibrary> appliedLib = lib;
			symbolTypeRef = ImportTypeLibraryObject(appliedLib, n);
			if (symbolTypeRef)
			{
				m_logger->LogDebug("pe: type library '%s' found hit for '%s'", lib->GetGuid().c_str(), name.c_str());
				RecordImportedObjectLibrary(GetDefaultPlatform(), address, appliedLib, n);
			}
		}
	}

	m_symbolQueue->Append(
		[=]() {
			// If name does not start with alphabetic character or symbol, prepend an underscore
			string rawName = name;
			if (!(((name[0] >= 'A') && (name[0] <= 'Z')) || ((name[0] >= 'a') && (name[0] <= 'z')) || (name[0] == '_')
					|| (name[0] == '?') || (name[0] == '$') || (name[0] == '@')))
				rawName = "_" + name;

			string shortName = rawName;
			string fullName = rawName;
			Ref<Type> typeRef = symbolTypeRef;

			if (m_arch && name.size() > 0)
			{
				QualifiedName demangleName;
				Ref<Type> demangledType;
				if (name[0] == '?')
				{
					if (DemangleMS(m_arch, name, demangledType, demangleName, m_simplifyTemplates))
					{
						shortName = demangleName.GetString();
						fullName = shortName + demangledType->GetStringAfterName();
						if (!typeRef && m_extractMangledTypes && !GetDefaultPlatform()->GetFunctionByName(rawName))
							typeRef = demangledType;
					}
					else if (!m_extractMangledTypes && DemangleLLVM(rawName, demangleName, m_simplifyTemplates))
					{
						shortName = demangleName.GetString();
						fullName = shortName;
					}
					else
					{
						m_logger->LogDebug("Failed to demangle: '%s'\n", name.c_str());
					}
				}
				else if (IsGNU3MangledString(rawName))
				{
					if (DemangleGNU3(m_arch, rawName, demangledType, demangleName, m_simplifyTemplates))
					{
						shortName = demangleName.GetString();
						fullName = shortName;
						if (demangledType)
							fullName += demangledType->GetStringAfterName();
						if (!typeRef && m_extractMangledTypes && !GetDefaultPlatform()->GetFunctionByName(rawName))
							typeRef = demangledType;
					}
					else if (!m_extractMangledTypes && DemangleLLVM(rawName, demangleName, m_simplifyTemplates))
					{
						shortName = demangleName.GetString();
						fullName = shortName;
					}
					else
					{
						m_logger->LogDebug("Failed to demangle name: '%s'\n", rawName.c_str());
					}
				}
				// Not a mangled string
			}

			NameSpace ns(dll);
			if (type == ExternalSymbol)
				ns = GetExternalNameSpace();

			return pair<Ref<Symbol>, Ref<Type>>(
				new Symbol(type, shortName, fullName, rawName, address, binding, ns, ordinal),
				typeRef);
		},
		[this](Symbol* symbol, Type* type) {
			DefineAutoSymbolAndVariableOrFunction(GetDefaultPlatform(), symbol, type);
		});
}


uint64_t PEView::PerformGetEntryPoint() const
{
	return m_imageBase + m_entryPoint;
}


size_t PEView::PerformGetAddressSize() const
{
	return m_is64 ? 8 : 4;
}


PEViewType::PEViewType() : BinaryViewType("PE", "PE")
{
	m_logger = LogRegistry::CreateLogger("BinaryView");
}


Ref<BinaryView> PEViewType::Create(BinaryView* data)
{
	try
	{
		return new PEView(data);
	}
	catch (std::exception& e)
	{
		m_logger->LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}


Ref<BinaryView> PEViewType::Parse(BinaryView* data)
{
	try
	{
		return new PEView(data, true);
	}
	catch (std::exception& e)
	{
		m_logger->LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}


bool PEViewType::IsTypeValidForData(BinaryView* data)
{
	// Check MZ header signature
	DataBuffer sig = data->ReadBuffer(0, 2);
	if (sig.GetLength() != 2)
		return false;
	if (memcmp(sig.GetData(), "MZ", 2) != 0)
		return false;

	BinaryReader reader(data, LittleEndian);

	// Read PE offset
	uint32_t peOfs;
	reader.Seek(0x3c);
	if (!reader.TryRead32(peOfs))
		return false;

	// Check PE signature
	DataBuffer peSig = data->ReadBuffer(peOfs, 4);
	if (peSig.GetLength() != 4)
		return false;
	if (memcmp(peSig.GetData(), "PE\0\0", 4) != 0)
		return false;

	// Check optional header signature
	uint16_t magic;
	reader.Seek(peOfs + 24);
	if (!reader.TryRead16(magic))
		return false;

	return (magic == 0x10b) || (magic == 0x20b);
}


Ref<Settings> PEViewType::GetLoadSettingsForData(BinaryView* data)
{
	Ref<BinaryView> viewRef = Parse(data);
	if (!viewRef || !viewRef->Init())
	{
		m_logger->LogError("View type '%s' could not be created", GetName().c_str());
		return nullptr;
	}

	Ref<Settings> settings = GetDefaultLoadSettingsForData(viewRef);

	// specify default load settings that can be overridden
	vector<string> overrides = {"loader.imageBase", "loader.platform"};
	if (!viewRef->IsRelocatable())
		settings->UpdateProperty("loader.imageBase", "message", "Note: File indicates image is not relocatable.");

	for (const auto& override : overrides)
	{
		if (settings->Contains(override))
			settings->UpdateProperty(override, "readOnly", false);
	}

	// register additional settings
	settings->RegisterSetting("loader.pe.processCfgTable",
			R"({
			"title" : "Process PE Control Flow Guard Table",
			"type" : "boolean",
			"default" : true,
			"description" : "Add function starts sourced from the Control Flow Guard (CFG) table to the core for analysis."
			})");

	settings->RegisterSetting("loader.pe.processExceptionTable",
			R"({
			"title" : "Process PE Exception Handling Table",
			"type" : "boolean",
			"default" : true,
			"description" : "Add function starts sourced from the Exception Handling table (.pdata) to the core for analysis."
			})");

	settings->RegisterSetting("loader.pe.processSehTable",
			R"({
			"title" : "Process PE Structured Exception Handling Table",
			"type" : "boolean",
			"default" : true,
			"description" : "Add function starts sourced from the Structured Exception Handling (SEH) table to the core for analysis."
			})");

	return settings;
}


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifdef DEMO_EDITION
	bool PEPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		InitPEViewType();
		InitCOFFViewType();
		InitTEViewType();
		return true;
	}
}
