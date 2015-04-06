#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


InstructionInfo::InstructionInfo()
{
	length = 0;
	branchCount = 0;
}


void InstructionInfo::AddBranch(BNBranchType type, uint64_t target, Architecture* arch)
{
	if (branchCount >= BN_MAX_INSTRUCTION_BRANCHES)
		return;
	branchType[branchCount] = type;
	branchTarget[branchCount] = target;
	branchArch[branchCount++] = arch ? arch->GetArchitectureObject() : nullptr;
}


InstructionTextToken::InstructionTextToken(): type(TextToken), value(0)
{
}


InstructionTextToken::InstructionTextToken(BNInstructionTextTokenType t, const std::string& txt, uint64_t val) :
	type(t), text(txt), value(val)
{
}


Architecture::Architecture(BNArchitecture* arch): m_arch(arch)
{
}


Architecture::Architecture(const string& name): m_nameForRegister(name)
{
}


BNEndianness Architecture::GetEndiannessCallback(void* ctxt)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->GetEndianness();
}


size_t Architecture::GetAddressSizeCallback(void* ctxt)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->GetAddressSize();
}


bool Architecture::GetInstructionInfoCallback(void* ctxt, const uint8_t* data, uint64_t addr,
                                              size_t maxLen, BNInstructionInfo* result)
{
	Architecture* arch = (Architecture*)ctxt;

	InstructionInfo info;
	bool ok = arch->GetInstructionInfo(data, addr, maxLen, info);
	*result = info;
	return ok;
}


bool Architecture::GetInstructionTextCallback(void* ctxt, const uint8_t* data, uint64_t addr,
                                              size_t* len, BNInstructionTextToken** result, size_t* count)
{
	Architecture* arch = (Architecture*)ctxt;

	vector<InstructionTextToken> tokens;
	bool ok = arch->GetInstructionText(data, addr, *len, tokens);
	if (!ok)
	{
		*result = nullptr;
		*count = 0;
		return false;
	}

	*count = tokens.size();
	*result = new BNInstructionTextToken[tokens.size()];
	for (size_t i = 0; i < tokens.size(); i++)
	{
		(*result)[i].type = tokens[i].type;
		(*result)[i].text = BNAllocString(tokens[i].text.c_str());
		(*result)[i].value = tokens[i].value;
	}
	return true;
}


void Architecture::FreeInstructionTextCallback(BNInstructionTextToken* tokens, size_t count)
{
	for (size_t i = 0; i < count; i++)
		BNFreeString(tokens[i].text);
	delete[] tokens;
}


bool Architecture::AssembleCallback(void* ctxt, const char* code, uint64_t addr, BNDataBuffer* result, char** errors)
{
	Architecture* arch = (Architecture*)ctxt;
	DataBuffer buf;
	string errorStr;
	bool ok = arch->Assemble(code, addr, buf, errorStr);

	BNSetDataBufferContents(result, buf.GetData(), buf.GetLength());
	*errors = BNAllocString(errorStr.c_str());
	return ok;
}


void Architecture::Register(Architecture* arch)
{
	BNCustomArchitecture callbacks;
	callbacks.context = arch;
	callbacks.getEndianness = GetEndiannessCallback;
	callbacks.getAddressSize = GetAddressSizeCallback;
	callbacks.getInstructionInfo = GetInstructionInfoCallback;
	callbacks.getInstructionText = GetInstructionTextCallback;
	callbacks.freeInstructionText = FreeInstructionTextCallback;
	callbacks.assemble = AssembleCallback;
	arch->m_arch = BNRegisterArchitecture(arch->m_nameForRegister.c_str(), &callbacks);
}


Ref<Architecture> Architecture::GetByName(const string& name)
{
	BNArchitecture* arch = BNGetArchitectureByName(name.c_str());
	if (!arch)
		return nullptr;
	return new CoreArchitecture(arch);
}


vector<Ref<Architecture>> Architecture::GetList()
{
	BNArchitecture** archs;
	size_t count;
	archs = BNGetArchitectureList(&count);

	vector<Ref<Architecture>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreArchitecture(archs[i]));

	BNFreeArchitectureList(archs);
	return result;
}


string Architecture::GetName() const
{
	char* name = BNGetArchitectureName(m_arch);
	string result = name;
	BNFreeString(name);
	return result;
}


CoreArchitecture::CoreArchitecture(BNArchitecture* arch): Architecture(arch)
{
}


BNEndianness CoreArchitecture::GetEndianness() const
{
	return BNGetArchitectureEndianness(m_arch);
}


size_t CoreArchitecture::GetAddressSize() const
{
	return BNGetArchitectureAddressSize(m_arch);
}


bool CoreArchitecture::GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result)
{
	return BNGetInstructionInfo(m_arch, data, addr, maxLen, &result);
}


bool CoreArchitecture::GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len, std::vector<InstructionTextToken>& result)
{
	BNInstructionTextToken* tokens = nullptr;
	size_t count = 0;
	if (!BNGetInstructionText(m_arch, data, addr, &len, &tokens, &count))
		return false;

	for (size_t i = 0; i < count; i++)
		result.push_back(InstructionTextToken(tokens[i].type, tokens[i].text, tokens[i].value));

	BNFreeInstructionText(tokens, count);
	return true;
}


bool CoreArchitecture::Assemble(const string& code, uint64_t addr, DataBuffer& result, string& errors)
{
	char* errorStr = nullptr;
	bool ok = BNAssemble(m_arch, code.c_str(), addr, result.GetBufferObject(), &errorStr);
	if (errorStr)
	{
		errors = errorStr;
		BNFreeString(errorStr);
	}
	return ok;
}
